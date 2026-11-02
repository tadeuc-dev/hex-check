#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hex_check.py — Inspetor e verificador de transações Bitcoin a partir do hex bruto.

O que ele faz:
  * Decodifica a transação (versão, entradas, saídas, witnesses, locktime, segwit);
  * Calcula txid, wtxid, tamanho, peso (weight) e vsize;
  * Mostra de onde vêm os fundos (endereços/valores das entradas) e para onde vão
    (endereços/valores das saídas), decodificando os scripts;
  * Calcula a taxa (fee) e a taxa por vbyte;
  * Valida as assinaturas:
      - ECDSA (legacy) para P2PK, P2PKH, P2SH e multisig;
      - ECDSA (BIP143) para P2WPKH, P2SH-P2WPKH, P2WSH e multisig em witness;
      - Schnorr (BIP340/BIP341) para P2TR (key path);
  * Emite um veredito: válida, inválida ou indeterminada (quando faltam prevouts).

Os dados dos prevouts (valor e scriptPubKey das moedas gastas) são necessários
para calcular a taxa e validar assinaturas. O script tenta obtê-los via API
(mempool.space) e permite informá-los manualmente com --prevout.

Uso:
    python3 hex_check.py <HEX>
    python3 hex_check.py -f tx.hex
    cat tx.hex | python3 hex_check.py
    python3 hex_check.py --no-network <HEX>
    python3 hex_check.py --prevout TXID:VOUT=SATS[:SCRIPT_PUBKEY_HEX] <HEX>
    python3 hex_check.py --network testnet <HEX>
    python3 hex_check.py --json <HEX>

Observações:
    * Nenhuma biblioteca externa é necessária (apenas a biblioteca padrão).
    * A verificação é estrutural + de assinaturas; não substitui um nó completo
      (não verifica regras dependentes da UTXO set, como maturidade de coinbase,
      limites de sigops, etc.).
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field

__version__ = "1.0"

COIN = 100_000_000
MAX_MONEY = 21_000_000 * COIN

# ---------------------------------------------------------------- redes ----

NETWORKS = {
    "mainnet": {"p2pkh": 0x00, "p2sh": 0x05, "hrp": "bc",
                "api": "https://mempool.space/api"},
    "testnet": {"p2pkh": 0x6F, "p2sh": 0xC4, "hrp": "tb",
                "api": "https://mempool.space/testnet/api"},
    "signet":  {"p2pkh": 0x6F, "p2sh": 0xC4, "hrp": "tb",
                "api": "https://mempool.space/signet/api"},
    "regtest": {"p2pkh": 0x6F, "p2sh": 0xC4, "hrp": "bcrt",
                "api": None},
}

SIGHASH_NAMES = {
    0x00: "SIGHASH_DEFAULT", 0x01: "SIGHASH_ALL", 0x02: "SIGHASH_NONE",
    0x03: "SIGHASH_SINGLE", 0x81: "SIGHASH_ALL|ANYONECANPAY",
    0x82: "SIGHASH_NONE|ANYONECANPAY", 0x83: "SIGHASH_SINGLE|ANYONECANPAY",
}

# ---------------------------------------------------------------- cores ----

_COLOR = False


def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if _COLOR else s


def bold(s: str) -> str:
    return _c("1", s)


def dim(s: str) -> str:
    return _c("2", s)


def green(s: str) -> str:
    return _c("32", s)


def red(s: str) -> str:
    return _c("31", s)


def yellow(s: str) -> str:
    return _c("33", s)


def cyan(s: str) -> str:
    return _c("36", s)


# ---------------------------------------------------------------- utils ----

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def sha256d(b: bytes) -> bytes:
    return sha256(sha256(b))


def tagged_hash(tag: str, msg: bytes) -> bytes:
    t = sha256(tag.encode())
    return sha256(t + t + msg)


def ripemd160_py(msg: bytes) -> bytes:
    """RIPEMD-160 em Python puro (fallback quando o OpenSSL não o oferece)."""
    r1 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
          7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
          3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
          1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
          4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13]
    r2 = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
          6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
          15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
          8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
          12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]
    s1 = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
          7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
          11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
          11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
          9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6]
    s2 = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
          9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
          9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
          15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
          8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]
    k1 = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
    k2 = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]
    mask = 0xFFFFFFFF

    def rol(x, n):
        return ((x << n) | (x >> (32 - n))) & mask

    def f(j, x, y, z):
        if j < 16:
            return x ^ y ^ z
        if j < 32:
            return (x & y) | (~x & z)
        if j < 48:
            return (x | ~y) ^ z
        if j < 64:
            return (x & z) | (y & ~z)
        return x ^ (y | ~z)

    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    data = bytearray(msg)
    bitlen = len(msg) * 8
    data.append(0x80)
    while len(data) % 64 != 56:
        data.append(0)
    data += bitlen.to_bytes(8, "little")

    for off in range(0, len(data), 64):
        x = [int.from_bytes(data[off + 4 * i:off + 4 * i + 4], "little")
             for i in range(16)]
        a, b, c, d, e = h
        a2, b2, c2, d2, e2 = h
        for j in range(80):
            t = (a + f(j, b, c, d) + x[r1[j]] + k1[j // 16]) & mask
            t = (rol(t, s1[j]) + e) & mask
            a, b, c, d, e = e, t, b, rol(c, 10), d
            t = (a2 + f(79 - j, b2, c2, d2) + x[r2[j]] + k2[j // 16]) & mask
            t = (rol(t, s2[j]) + e2) & mask
            a2, b2, c2, d2, e2 = e2, t, b2, rol(c2, 10), d2
        t = (h[1] + c + d2) & mask
        h[1] = (h[2] + d + e2) & mask
        h[2] = (h[3] + e + a2) & mask
        h[3] = (h[4] + a + b2) & mask
        h[4] = (h[0] + b + c2) & mask
        h[0] = t

    return b"".join(v.to_bytes(4, "little") for v in h)


def hash160(b: bytes) -> bytes:
    d = sha256(b)
    try:
        return hashlib.new("ripemd160", d).digest()
    except (ValueError, TypeError):
        return ripemd160_py(d)


def fmt_btc(sats: int) -> str:
    sign = "-" if sats < 0 else ""
    s = abs(int(sats))
    return f"{sign}{s // COIN}.{s % COIN:08d}"


def fmt_sats(sats: int) -> str:
    return f"{int(sats):,}".replace(",", ".")


def fmt_amount(sats: int) -> str:
    return f"{fmt_btc(sats)} BTC ({fmt_sats(sats)} sats)"


def fmt_time(ts: int) -> str:
    dt = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
    return dt.strftime("%d/%m/%Y %H:%M:%S UTC")


def fmt_locktime(lt: int) -> str:
    if lt == 0:
        return "0 (desativado)"
    if lt < 500_000_000:
        return f"{lt} (altura de bloco)"
    return f"{lt} ({fmt_time(lt)})"


def hexstr(b: bytes, maxlen: int | None = None) -> str:
    h = b.hex()
    if maxlen is not None and len(h) > maxlen:
        return h[:maxlen] + "…"
    return h


def encode_varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def u32(n: int) -> bytes:
    return int(n).to_bytes(4, "little")


def u64(n: int) -> bytes:
    return int(n).to_bytes(8, "little")


class ParseError(Exception):
    pass


class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def peek(self, n: int) -> bytes:
        return self.data[self.pos:self.pos + n]

    def read(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise ParseError(
                f"fim inesperado dos dados (precisa de {n} bytes, restam "
                f"{self.remaining()})")
        b = self.data[self.pos:self.pos + n]
        self.pos += n
        return b

    def u8(self) -> int:
        return self.read(1)[0]

    def u32(self) -> int:
        return int.from_bytes(self.read(4), "little")

    def i32(self) -> int:
        v = self.u32()
        return v - (1 << 32) if v >= (1 << 31) else v

    def u64(self) -> int:
        return int.from_bytes(self.read(8), "little")

    def varint(self) -> tuple[int, bool]:
        first = self.u8()
        if first < 0xFD:
            return first, True
        if first == 0xFD:
            v = int.from_bytes(self.read(2), "little")
            return v, v >= 0xFD
        if first == 0xFE:
            v = int.from_bytes(self.read(4), "little")
            return v, v > 0xFFFF
        v = int.from_bytes(self.read(8), "little")
        return v, v > 0xFFFFFFFF


# ------------------------------------------------------- base58 / bech32 ----

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    pad = len(b) - len(b.lstrip(b"\x00"))
    return "1" * pad + (out or "")


def b58check(payload: bytes) -> str:
    return b58encode(payload + sha256d(payload)[:4])


_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_CONST = 1
_BECH32M_CONST = 0x2BC830A3


def _bech32_polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= gen[i]
    return chk


def _bech32_hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _bech32_create_checksum(hrp, data, const):
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _convertbits(data, frombits, tobits):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def segwit_encode(hrp: str, witver: int, witprog: bytes) -> str:
    data = [witver] + _convertbits(witprog, 8, 5)
    const = _BECH32_CONST if witver == 0 else _BECH32M_CONST
    combined = data + _bech32_create_checksum(hrp, data, const)
    return hrp + "1" + "".join(_BECH32_CHARSET[d] for d in combined)


# --------------------------------------------------------- secp256k1 ----

P_FIELD = 2**256 - 2**32 - 977
N_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G_POINT = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
           0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P_FIELD == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1) * pow(2 * y1, -1, P_FIELD) % P_FIELD
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P_FIELD) % P_FIELD
    x3 = (lam * lam - x1 - x2) % P_FIELD
    y3 = (lam * (x1 - x3) - y1) % P_FIELD
    return (x3, y3)


def _point_mul(k, pt):
    k %= N_ORDER
    result = None
    addend = pt
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def decode_pubkey(pk: bytes):
    if len(pk) == 33 and pk[0] in (2, 3):
        x = int.from_bytes(pk[1:], "big")
        if x >= P_FIELD:
            return None
        y2 = (pow(x, 3, P_FIELD) + 7) % P_FIELD
        y = pow(y2, (P_FIELD + 1) // 4, P_FIELD)
        if (y * y - y2) % P_FIELD:
            return None
        if (y & 1) != (pk[0] & 1):
            y = P_FIELD - y
        return (x, y)
    if len(pk) == 65 and pk[0] == 4:
        x = int.from_bytes(pk[1:33], "big")
        y = int.from_bytes(pk[33:], "big")
        if x >= P_FIELD or y >= P_FIELD:
            return None
        if (y * y - (pow(x, 3, P_FIELD) + 7)) % P_FIELD:
            return None
        return (x, y)
    return None


def der_decode(sig: bytes) -> tuple[int, int]:
    if len(sig) < 8 or sig[0] != 0x30:
        raise ValueError("não é uma sequência DER")
    if sig[1] != len(sig) - 2:
        raise ValueError("tamanho DER incorreto")
    if sig[2] != 0x02:
        raise ValueError("faltou inteiro r")
    rlen = sig[3]
    r = int.from_bytes(sig[4:4 + rlen], "big")
    pos = 4 + rlen
    if pos + 2 > len(sig) or sig[pos] != 0x02:
        raise ValueError("faltou inteiro s")
    slen = sig[pos + 1]
    s = int.from_bytes(sig[pos + 2:pos + 2 + slen], "big")
    if pos + 2 + slen != len(sig):
        raise ValueError("bytes extras no DER")
    return r, s


def ecdsa_verify(msg: bytes, sig_der: bytes, pubkey: bytes) -> bool:
    try:
        r, s = der_decode(sig_der)
    except ValueError:
        return False
    if not (1 <= r < N_ORDER and 1 <= s < N_ORDER):
        return False
    q = decode_pubkey(pubkey)
    if q is None:
        return False
    z = int.from_bytes(msg, "big") % N_ORDER
    w = pow(s, -1, N_ORDER)
    point = _point_add(_point_mul((z * w) % N_ORDER, G_POINT),
                       _point_mul((r * w) % N_ORDER, q))
    return point is not None and (point[0] % N_ORDER) == r


def lift_x(x_bytes: bytes):
    if len(x_bytes) != 32:
        return None
    x = int.from_bytes(x_bytes, "big")
    if x >= P_FIELD:
        return None
    y2 = (pow(x, 3, P_FIELD) + 7) % P_FIELD
    y = pow(y2, (P_FIELD + 1) // 4, P_FIELD)
    if (y * y - y2) % P_FIELD:
        return None
    if y & 1:
        y = P_FIELD - y
    return (x, y)


def schnorr_verify(msg: bytes, xonly: bytes, sig: bytes) -> bool:
    if len(xonly) != 32 or len(sig) != 64:
        return False
    point = lift_x(xonly)
    if point is None:
        return False
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    if r >= P_FIELD or s >= N_ORDER:
        return False
    e = int.from_bytes(
        tagged_hash("BIP0340/challenge", sig[:32] + xonly + msg), "big"
    ) % N_ORDER
    rpoint = _point_add(_point_mul(s, G_POINT),
                        _point_mul((N_ORDER - e) % N_ORDER, point))
    if rpoint is None or (rpoint[1] & 1):
        return False
    return rpoint[0] == r


# ------------------------------------------------------------- opcodes ----

OPCODES = {
    0x00: "OP_0", 0x4F: "OP_1NEGATE", 0x50: "OP_RESERVED",
    0x51: "OP_1", 0x52: "OP_2", 0x53: "OP_3", 0x54: "OP_4", 0x55: "OP_5",
    0x56: "OP_6", 0x57: "OP_7", 0x58: "OP_8", 0x59: "OP_9", 0x5A: "OP_10",
    0x5B: "OP_11", 0x5C: "OP_12", 0x5D: "OP_13", 0x5E: "OP_14",
    0x5F: "OP_15", 0x60: "OP_16",
    0x61: "OP_NOP", 0x62: "OP_VER", 0x63: "OP_IF", 0x64: "OP_NOTIF",
    0x65: "OP_VERIF", 0x66: "OP_VERNOTIF", 0x67: "OP_ELSE",
    0x68: "OP_ENDIF", 0x69: "OP_VERIFY", 0x6A: "OP_RETURN",
    0x6B: "OP_TOALTSTACK", 0x6C: "OP_FROMALTSTACK", 0x6D: "OP_2DROP",
    0x6E: "OP_2DUP", 0x6F: "OP_3DUP", 0x70: "OP_2OVER", 0x71: "OP_2ROT",
    0x72: "OP_2SWAP", 0x73: "OP_IFDUP", 0x74: "OP_DEPTH", 0x75: "OP_DROP",
    0x76: "OP_DUP", 0x77: "OP_NIP", 0x78: "OP_OVER", 0x79: "OP_PICK",
    0x7A: "OP_ROLL", 0x7B: "OP_ROT", 0x7C: "OP_SWAP", 0x7D: "OP_TUCK",
    0x7E: "OP_CAT", 0x7F: "OP_SUBSTR", 0x80: "OP_LEFT", 0x81: "OP_RIGHT",
    0x82: "OP_SIZE", 0x83: "OP_INVERT", 0x84: "OP_AND", 0x85: "OP_OR",
    0x86: "OP_XOR", 0x87: "OP_EQUAL", 0x88: "OP_EQUALVERIFY",
    0x89: "OP_RESERVED1", 0x8A: "OP_RESERVED2", 0x8B: "OP_1ADD",
    0x8C: "OP_1SUB", 0x8D: "OP_2MUL", 0x8E: "OP_2DIV", 0x8F: "OP_NEGATE",
    0x90: "OP_ABS", 0x91: "OP_NOT", 0x92: "OP_0NOTEQUAL", 0x93: "OP_ADD",
    0x94: "OP_SUB", 0x95: "OP_MUL", 0x96: "OP_DIV", 0x97: "OP_MOD",
    0x98: "OP_LSHIFT", 0x99: "OP_RSHIFT", 0x9A: "OP_BOOLAND",
    0x9B: "OP_BOOLOR", 0x9C: "OP_NUMEQUAL", 0x9D: "OP_NUMEQUALVERIFY",
    0x9E: "OP_NUMNOTEQUAL", 0x9F: "OP_LESSTHAN", 0xA0: "OP_GREATERTHAN",
    0xA1: "OP_LESSTHANOREQUAL", 0xA2: "OP_GREATERTHANOREQUAL",
    0xA3: "OP_MIN", 0xA4: "OP_MAX", 0xA5: "OP_WITHIN",
    0xA6: "OP_RIPEMD160", 0xA7: "OP_SHA1", 0xA8: "OP_SHA256",
    0xA9: "OP_HASH160", 0xAA: "OP_HASH256", 0xAB: "OP_CODESEPARATOR",
    0xAC: "OP_CHECKSIG", 0xAD: "OP_CHECKSIGVERIFY",
    0xAE: "OP_CHECKMULTISIG", 0xAF: "OP_CHECKMULTISIGVERIFY",
    0xB0: "OP_NOP1", 0xB1: "OP_CHECKLOCKTIMEVERIFY",
    0xB2: "OP_CHECKSEQUENCEVERIFY", 0xB3: "OP_NOP4", 0xB4: "OP_NOP5",
    0xB5: "OP_NOP6", 0xB6: "OP_NOP7", 0xB7: "OP_NOP8", 0xB8: "OP_NOP9",
    0xB9: "OP_NOP10",
}


def opcode_name(op: int) -> str:
    return OPCODES.get(op, f"OP_UNKNOWN_0x{op:02x}")


def _read_push(script: bytes, i: int):
    """Lê um push em script[i:]. Retorna (data, novo_i) ou (None, i)."""
    if i >= len(script):
        return None, i
    op = script[i]
    i += 1
    if op == 0x00:
        return b"", i
    if 1 <= op <= 0x4B:
        n = op
    elif op == 0x4C:
        if i + 1 > len(script):
            return None, i
        n = script[i]
        i += 1
    elif op == 0x4D:
        if i + 2 > len(script):
            return None, i
        n = int.from_bytes(script[i:i + 2], "little")
        i += 2
    elif op == 0x4E:
        if i + 4 > len(script):
            return None, i
        n = int.from_bytes(script[i:i + 4], "little")
        i += 4
    else:
        return None, i - 1
    if i + n > len(script):
        return None, i
    return script[i:i + n], i + n


def script_pushes(script: bytes) -> list[bytes]:
    """Extrai apenas os pushes do script (levanta ValueError se houver opcode)."""
    items = []
    i = 0
    while i < len(script):
        before = i
        data, i = _read_push(script, i)
        if data is None:
            raise ValueError(
                f"opcode {opcode_name(script[before])} em vez de push")
        items.append(data)
    return items


def disassemble(script: bytes, maxlen: int = 80) -> str:
    parts = []
    i = 0
    while i < len(script):
        op = script[i]
        data, ni = _read_push(script, i)
        if data is not None:
            i = ni
            if len(data) <= 4:
                parts.append(f"PUSH[{len(data)}] 0x{data.hex()}" if data
                             else "OP_0")
            else:
                h = hexstr(data, maxlen)
                text = ""
                if data and all(32 <= c < 127 for c in data):
                    t = data.decode("ascii")
                    if len(t) > 40:
                        t = t[:40] + "…"
                    text = f' "{t}"'
                parts.append(f"PUSH[{len(data)}] 0x{h}{text}")
        else:
            parts.append(opcode_name(op))
            i += 1
    return " ".join(parts)


def multisig_parts(script: bytes):
    """Se o script for m-de-n CHECKMULTISIG, retorna (m, [pubkeys])."""
    if len(script) < 3:
        return None
    if not (0x51 <= script[0] <= 0x60):
        return None
    m = script[0] - 0x50
    i = 1
    pubs = []
    while i < len(script) and 1 <= script[i] <= 0x4B:
        data, ni = _read_push(script, i)
        if data is None:
            return None
        pubs.append(data)
        i = ni
    if i >= len(script) or not (0x51 <= script[i] <= 0x60):
        return None
    n = script[i] - 0x50
    i += 1
    if i != len(script) - 1 or script[i] != 0xAE:
        return None
    if n != len(pubs) or not (1 <= m <= n <= 20):
        return None
    return m, pubs


def classify_script(spk: bytes) -> str:
    if len(spk) == 25 and spk[0] == 0x76 and spk[1] == 0xA9 \
            and spk[2] == 0x14 and spk[23] == 0x88 and spk[24] == 0xAC:
        return "p2pkh"
    if len(spk) == 23 and spk[0] == 0xA9 and spk[1] == 0x14 \
            and spk[22] == 0x87:
        return "p2sh"
    if len(spk) == 22 and spk[0] == 0x00 and spk[1] == 0x14:
        return "p2wpkh"
    if len(spk) == 34 and spk[0] == 0x00 and spk[1] == 0x20:
        return "p2wsh"
    if len(spk) == 34 and spk[0] == 0x51 and spk[1] == 0x20:
        return "p2tr"
    if spk and spk[0] == 0x6A:
        return "op_return"
    if len(spk) == 35 and spk[0] == 0x21 and spk[34] == 0xAC:
        return "p2pk"
    if len(spk) == 67 and spk[0] == 0x41 and spk[66] == 0xAC:
        return "p2pk"
    if multisig_parts(spk):
        return "multisig"
    if len(spk) >= 2 and spk[0] == 0x00 and 2 <= spk[1] <= 40:
        return "witness_v0"
    if len(spk) >= 2 and 0x51 <= spk[0] <= 0x60 and 2 <= spk[1] <= 40:
        return f"witness_v{spk[0] - 0x50}"
    return "desconhecido"


TYPE_LABEL = {
    "p2pkh": "P2PKH", "p2sh": "P2SH", "p2wpkh": "P2WPKH (SegWit v0)",
    "p2wsh": "P2WSH (SegWit v0)", "p2tr": "P2TR (Taproot)",
    "op_return": "OP_RETURN", "p2pk": "P2PK", "multisig": "Multisig",
    "desconhecido": "Desconhecido",
}


def type_label(t: str) -> str:
    return TYPE_LABEL.get(t, t.upper())


def script_address(spk: bytes, network: str = "mainnet"):
    t = classify_script(spk)
    net = NETWORKS[network]
    if t == "p2pkh":
        return b58check(bytes([net["p2pkh"]]) + spk[3:23])
    if t == "p2sh":
        return b58check(bytes([net["p2sh"]]) + spk[2:22])
    if t == "p2wpkh":
        return segwit_encode(net["hrp"], 0, spk[2:22])
    if t == "p2wsh":
        return segwit_encode(net["hrp"], 0, spk[2:34])
    if t == "p2tr":
        return segwit_encode(net["hrp"], 1, spk[2:34])
    if t == "p2pk":
        return b58check(bytes([net["p2pkh"]]) + hash160(spk[1:-1]))
    return None


# ------------------------------------------------------- transação ----

@dataclass
class TxIn:
    prev_txid: bytes          # 32 bytes, little-endian (como vem no hex)
    prev_vout: int
    script_sig: bytes
    sequence: int
    witness: list[bytes] = field(default_factory=list)

    @property
    def prev_txid_hex(self) -> str:
        return self.prev_txid[::-1].hex()

    @property
    def outpoint(self) -> str:
        return f"{self.prev_txid_hex}:{self.prev_vout}"


@dataclass
class TxOut:
    value: int
    script_pubkey: bytes


@dataclass
class Transaction:
    version: int
    inputs: list[TxIn]
    outputs: list[TxOut]
    locktime: int
    segwit: bool = False
    flag: int = 0

    # -- serialização -------------------------------------------------
    def _serialize_preimage(self, include_witness: bool) -> bytes:
        out = bytearray()
        out += u32(self.version)
        if self.segwit and include_witness:
            out += b"\x00" + bytes([self.flag or 1])
        out += encode_varint(len(self.inputs))
        for inp in self.inputs:
            out += inp.prev_txid
            out += u32(inp.prev_vout)
            out += encode_varint(len(inp.script_sig))
            out += inp.script_sig
            out += u32(inp.sequence)
        out += encode_varint(len(self.outputs))
        for o in self.outputs:
            out += u64(o.value)
            out += encode_varint(len(o.script_pubkey))
            out += o.script_pubkey
        if self.segwit and include_witness:
            for inp in self.inputs:
                out += encode_varint(len(inp.witness))
                for item in inp.witness:
                    out += encode_varint(len(item))
                    out += item
        out += u32(self.locktime)
        return bytes(out)

    def serialize(self) -> bytes:
        return self._serialize_preimage(True)

    def serialize_legacy(self) -> bytes:
        return self._serialize_preimage(False)

    # -- hashes / tamanhos --------------------------------------------
    @property
    def txid(self) -> str:
        return sha256d(self.serialize_legacy())[::-1].hex()

    @property
    def wtxid(self) -> str:
        return sha256d(self.serialize())[::-1].hex()

    @property
    def size(self) -> int:
        return len(self.serialize())

    @property
    def base_size(self) -> int:
        return len(self.serialize_legacy())

    @property
    def weight(self) -> int:
        return self.base_size * 3 + self.size

    @property
    def vsize(self) -> int:
        return (self.weight + 3) // 4

    @property
    def is_coinbase(self) -> bool:
        return (len(self.inputs) == 1
                and self.inputs[0].prev_txid == b"\x00" * 32
                and self.inputs[0].prev_vout == 0xFFFFFFFF)

    @property
    def rbf(self) -> bool:
        return any(i.sequence < 0xFFFFFFFE for i in self.inputs)


def parse_tx(raw: bytes) -> tuple[Transaction, list[str]]:
    r = Reader(raw)
    warnings: list[str] = []
    version = r.i32()

    segwit = False
    flag = 0
    if r.remaining() >= 2 and r.peek(2) == b"\x00\x01":
        segwit = True
        flag = 1
        r.read(2)
    elif r.remaining() >= 2 and r.peek(1) == b"\x00":
        # possível marker com flag desconhecido
        if r.peek(2)[1] != 0:
            warnings.append(
                f"marker/flag incomum: 00{r.peek(2)[1]:02x} "
                "(esperado 0001)")

    n_in, canon = r.varint()
    if not canon:
        warnings.append("varint não canônico na contagem de entradas")
    if n_in > 1_000_000:
        raise ParseError(f"número absurdo de entradas: {n_in}")
    if n_in == 0:
        warnings.append("transação sem entradas (inválida)")
    inputs = []
    for _ in range(n_in):
        prev_txid = r.read(32)
        prev_vout = r.u32()
        slen, canon = r.varint()
        if not canon:
            warnings.append("varint não canônico no scriptSig")
        if slen > r.remaining():
            raise ParseError("scriptSig maior que os dados restantes")
        script_sig = r.read(slen)
        sequence = r.u32()
        inputs.append(TxIn(prev_txid, prev_vout, script_sig, sequence))

    n_out, canon = r.varint()
    if not canon:
        warnings.append("varint não canônico na contagem de saídas")
    if n_out > 1_000_000:
        raise ParseError(f"número absurdo de saídas: {n_out}")
    if n_out == 0:
        warnings.append("transação sem saídas (inválida)")
    outputs = []
    for _ in range(n_out):
        value = r.u64()
        plen, canon = r.varint()
        if not canon:
            warnings.append("varint não canônico no scriptPubKey")
        if plen > r.remaining():
            raise ParseError("scriptPubKey maior que os dados restantes")
        spk = r.read(plen)
        outputs.append(TxOut(value, spk))

    if segwit:
        for inp in inputs:
            count, canon = r.varint()
            if not canon:
                warnings.append("varint não canônico na witness")
            if count > 1_000_000:
                raise ParseError(f"witness com itens demais: {count}")
            items = []
            for _ in range(count):
                ilen, _ = r.varint()
                if ilen > r.remaining():
                    raise ParseError("item de witness maior que os dados")
                items.append(r.read(ilen))
            inp.witness = items

    locktime = r.u32()
    if r.remaining():
        warnings.append(f"{r.remaining()} byte(s) extra(s) após o locktime")

    tx = Transaction(version, inputs, outputs, locktime, segwit, flag)
    return tx, warnings


# ---------------------------------------------------------- sighashes ----

def _serialize_outpoints(inputs) -> bytes:
    return b"".join(i.prev_txid + u32(i.prev_vout) for i in inputs)


def _serialize_outputs(outputs) -> bytes:
    out = bytearray()
    for o in outputs:
        out += u64(o.value)
        out += encode_varint(len(o.script_pubkey))
        out += o.script_pubkey
    return bytes(out)


def legacy_sighash(tx: Transaction, idx: int, script_code: bytes,
                   hash_type: int) -> bytes:
    base = hash_type & 0x1F
    anyone = bool(hash_type & 0x80)
    if base not in (1, 2, 3):
        raise ValueError(f"tipo de sighash inválido: 0x{hash_type:02x}")

    if base == 3 and idx >= len(tx.outputs):
        return b"\x01" * 32

    out = bytearray()
    out += u32(tx.version)
    ins = [tx.inputs[idx]] if anyone else tx.inputs
    out += encode_varint(len(ins))
    for j, inp in enumerate(ins):
        cur = True if anyone else (j == idx)
        out += inp.prev_txid
        out += u32(inp.prev_vout)
        sc = script_code if cur else b""
        out += encode_varint(len(sc))
        out += sc
        seq = inp.sequence
        if not cur and base in (2, 3):
            seq = 0
        out += u32(seq)
    if base == 2:
        out += b"\x00"
    elif base == 3:
        out += encode_varint(idx + 1)
        for _ in range(idx):
            out += b"\xff" * 8 + b"\x00"
        o = tx.outputs[idx]
        out += u64(o.value) + encode_varint(len(o.script_pubkey)) \
            + o.script_pubkey
    else:
        out += encode_varint(len(tx.outputs))
        out += _serialize_outputs(tx.outputs)
    out += u32(tx.locktime)
    out += u32(hash_type & 0xFFFFFFFF)
    return sha256d(bytes(out))


def bip143_sighash(tx: Transaction, idx: int, script_code: bytes,
                   value: int, hash_type: int) -> bytes:
    base = hash_type & 0x1F
    anyone = bool(hash_type & 0x80)
    if base not in (1, 2, 3):
        raise ValueError(f"tipo de sighash inválido: 0x{hash_type:02x}")
    if value is None:
        raise ValueError("valor do prevout é necessário (BIP143)")

    if anyone:
        hash_prevouts = b"\x00" * 32
    else:
        hash_prevouts = sha256d(_serialize_outpoints(tx.inputs))

    if anyone or base in (2, 3):
        hash_sequence = b"\x00" * 32
    else:
        hash_sequence = sha256d(b"".join(u32(i.sequence)
                                         for i in tx.inputs))

    if base not in (2, 3):
        hash_outputs = sha256d(_serialize_outputs(tx.outputs))
    elif base == 3 and idx < len(tx.outputs):
        hash_outputs = sha256d(_serialize_outputs([tx.outputs[idx]]))
    else:
        hash_outputs = b"\x00" * 32

    inp = tx.inputs[idx]
    preimage = bytearray()
    preimage += u32(tx.version)
    preimage += hash_prevouts
    preimage += hash_sequence
    preimage += inp.prev_txid + u32(inp.prev_vout)
    preimage += encode_varint(len(script_code)) + script_code
    preimage += u64(value)
    preimage += u32(inp.sequence)
    preimage += hash_outputs
    preimage += u32(tx.locktime)
    preimage += u32(hash_type & 0xFFFFFFFF)
    return sha256d(bytes(preimage))


def bip341_sighash(tx: Transaction, idx: int, prevouts, hash_type: int,
                   annex: bytes | None = None) -> bytes:
    """Sighash do Taproot (key path ou script path com ext_flag dado)."""
    if hash_type not in (0x00, 0x01):
        raise ValueError(
            f"sighash Taproot 0x{hash_type:02x} não suportado "
            "(use SIGHASH_DEFAULT ou SIGHASH_ALL)")
    for p in prevouts:
        if p is None or p.get("value") is None or p.get("spk") is None:
            raise ValueError("todos os prevouts são necessários (BIP341)")

    sha_prevouts = sha256(_serialize_outpoints(tx.inputs))
    sha_amounts = sha256(b"".join(u64(p["value"]) for p in prevouts))
    sha_spks = sha256(b"".join(
        encode_varint(len(p["spk"])) + p["spk"] for p in prevouts))
    sha_sequences = sha256(b"".join(u32(i.sequence) for i in tx.inputs))
    sha_outputs = sha256(_serialize_outputs(tx.outputs))

    spend_type = 0 if annex is None else 1
    msg = bytearray()
    msg += bytes([hash_type])
    msg += u32(tx.version)
    msg += u32(tx.locktime)
    msg += sha_prevouts
    msg += sha_amounts
    msg += sha_spks
    msg += sha_sequences
    msg += sha_outputs
    msg += bytes([spend_type])
    msg += u32(idx)
    if annex is not None:
        msg += sha256(encode_varint(len(annex)) + annex)
    # epoch 0x00 é prefixado à mensagem (BIP341)
    return tagged_hash("TapSighash", b"\x00" + bytes(msg))


# ---------------------------------------------------- verificação ----

def _sighash_name(ht: int | None) -> str:
    if ht is None:
        return "?"
    return SIGHASH_NAMES.get(ht, f"0x{ht:02x}")


def _ecdsa_check(tx: Transaction, idx: int, script_code: bytes,
                 value: int | None, sig_push: bytes, pubkey: bytes,
                 segwit: bool) -> dict:
    if len(sig_push) < 9:
        return {"status": "invalid", "detail": "assinatura curta demais"}
    hash_type = sig_push[-1]
    der = sig_push[:-1]
    if (hash_type & 0x1F) not in (1, 2, 3):
        return {"status": "invalid",
                "detail": f"tipo de sighash inválido 0x{hash_type:02x}"}
    try:
        r, s = der_decode(der)
    except ValueError as exc:
        return {"status": "invalid", "detail": f"DER inválido: {exc}"}
    if not (1 <= r < N_ORDER and 1 <= s < N_ORDER):
        return {"status": "invalid", "detail": "valores r/s fora de faixa"}
    if decode_pubkey(pubkey) is None:
        return {"status": "invalid", "detail": "chave pública inválida"}
    notes = []
    if s > N_ORDER // 2:
        notes.append("s alto (high-S)")
    if len(der) > 72:
        notes.append("codificação DER não compacta")
    if segwit:
        if value is None:
            return {"status": "unknown",
                    "detail": "valor do prevout necessário para BIP143"}
        msg = bip143_sighash(tx, idx, script_code, value, hash_type)
        scheme = "ECDSA (BIP143)"
    else:
        msg = legacy_sighash(tx, idx, script_code, hash_type)
        scheme = "ECDSA (legacy)"
    ok = ecdsa_verify(msg, der, pubkey)
    return {
        "status": "valid" if ok else "invalid",
        "scheme": scheme,
        "sighash": hash_type,
        "notes": notes,
        "detail": "" if ok else "assinatura ECDSA não confere",
    }


def evaluate_script(script: bytes, stack: list[bytes], tx: Transaction,
                    idx: int, value: int | None, segwit: bool) -> dict:
    """Valida scripts padrão (P2PKH/P2PK/multisig) com uma pilha de dados."""
    t = classify_script(script)

    if t == "p2pkh":
        if len(stack) < 2:
            return {"status": "invalid", "detail": "faltam sig/pubkey na pilha"}
        sig, pub = stack[-2], stack[-1]
        if hash160(pub) != script[3:23]:
            return {"status": "invalid",
                    "detail": "hash160 da chave pública não confere"}
        return _ecdsa_check(tx, idx, script, value, sig, pub, segwit)

    if t == "p2pk":
        if not stack:
            return {"status": "invalid", "detail": "assinatura ausente"}
        return _ecdsa_check(tx, idx, script, value, stack[-1],
                            script[1:-1], segwit)

    if t == "multisig":
        m, pubs = multisig_parts(script)
        sigs = [s for s in stack if s]
        if len(sigs) != m:
            return {"status": "invalid",
                    "detail": f"esperava {m} assinatura(s), achou {len(sigs)}"}
        pi = 0
        used = []
        for sig in sigs:
            matched = None
            while pi < len(pubs):
                pub = pubs[pi]
                pi += 1
                res = _ecdsa_check(tx, idx, script, value, sig, pub, segwit)
                if res["status"] in ("unknown", "invalid") \
                        and res.get("detail", "").startswith("DER"):
                    continue
                if res["status"] == "unknown":
                    return res
                if res["status"] == "valid":
                    matched = res
                    break
            if matched is None:
                return {"status": "invalid",
                        "detail": "assinatura não corresponde a nenhuma chave"}
            used.append(matched)
        notes = [n for r in used for n in r.get("notes", [])]
        return {"status": "valid", "scheme": used[0]["scheme"],
                "sighash": used[0]["sighash"], "notes": notes,
                "detail": f"{m}-de-{len(pubs)} multisig"}

    return {"status": "unsupported",
            "detail": f"script {type_label(t)} não suportado para verificação"}


def _taproot_check(tx: Transaction, idx: int, spk: bytes, witness: list[bytes],
                   prevouts, value) -> dict:
    stack = list(witness)
    annex = None
    if len(stack) >= 2 and stack[-1][:1] == b"\x50":
        annex = stack.pop()
    if len(stack) != 1:
        return {"status": "unsupported",
                "detail": "Taproot script path (tapscript) não suportado"}
    sig = stack[0]
    if len(sig) == 64:
        hash_type = 0x00
    elif len(sig) == 65:
        hash_type = sig[64]
        if hash_type == 0x00:
            return {"status": "invalid",
                    "detail": "SIGHASH_DEFAULT com assinatura de 65 bytes"}
    else:
        return {"status": "invalid",
                "detail": f"tamanho de assinatura Schnorr inválido ({len(sig)})"}
    if hash_type not in (0x00, 0x01):
        return {"status": "unsupported",
                "detail": f"sighash Taproot 0x{hash_type:02x} não suportado"}
    try:
        msg = bip341_sighash(tx, idx, prevouts, hash_type, annex)
    except ValueError as exc:
        return {"status": "unknown", "detail": str(exc)}
    ok = schnorr_verify(msg, spk[2:34], sig[:64])
    return {
        "status": "valid" if ok else "invalid",
        "scheme": "Schnorr (BIP340/BIP341)",
        "sighash": hash_type,
        "notes": [],
        "detail": "key path" if ok else "assinatura Schnorr não confere",
    }


def verify_input(tx: Transaction, idx: int, prevout: dict | None,
                 prevouts: list) -> dict:
    inp = tx.inputs[idx]
    if tx.is_coinbase:
        return {"status": "n/a", "detail": "entrada coinbase (sem assinatura)"}
    if prevout is None:
        return {"status": "unknown",
                "detail": "prevout não encontrado (sem valor/scriptPubKey)"}
    spk = prevout.get("spk")
    value = prevout.get("value")
    if spk is None:
        return {"status": "unknown",
                "detail": "scriptPubKey do prevout desconhecido"}
    t = classify_script(spk)
    notes = []

    try:
        if t == "p2wpkh":
            if inp.script_sig:
                notes.append("scriptSig não vazio em P2WPKH nativo (inválido)")
            if len(inp.witness) != 2:
                return {"status": "invalid",
                        "detail": f"witness deveria ter 2 itens, tem "
                                  f"{len(inp.witness)}"}
            sig, pub = inp.witness
            if hash160(pub) != spk[2:22]:
                return {"status": "invalid",
                        "detail": "hash160 da chave pública não confere"}
            script_code = b"\x76\xa9\x14" + spk[2:22] + b"\x88\xac"
            res = _ecdsa_check(tx, idx, script_code, value, sig, pub, True)

        elif t == "p2wsh":
            if inp.script_sig:
                notes.append("scriptSig não vazio em P2WSH nativo (inválido)")
            if not inp.witness:
                return {"status": "invalid", "detail": "witness vazio"}
            witness_script = inp.witness[-1]
            if sha256(witness_script) != spk[2:34]:
                return {"status": "invalid",
                        "detail": "sha256 do witness script não confere"}
            res = evaluate_script(witness_script, inp.witness[:-1], tx, idx,
                                  value, True)

        elif t == "p2tr":
            res = _taproot_check(tx, idx, spk, inp.witness, prevouts, value)

        elif t == "p2sh":
            pushes = script_pushes(inp.script_sig)
            if not pushes:
                return {"status": "invalid", "detail": "scriptSig sem redeem script"}
            redeem = pushes[-1]
            if hash160(redeem) != spk[2:22]:
                return {"status": "invalid",
                        "detail": "hash160 do redeem script não confere"}
            if len(pushes) > 1 and not (
                    len(redeem) == 22 and redeem[0] == 0x00
                    and redeem[1] == 0x14):
                notes.append("scriptSig tem pushes além do redeem script")
            rtype = classify_script(redeem)
            if rtype == "p2wpkh":
                if len(inp.witness) != 2:
                    return {"status": "invalid",
                            "detail": "witness P2SH-P2WPKH deveria ter 2 itens"}
                sig, pub = inp.witness
                if hash160(pub) != redeem[2:22]:
                    return {"status": "invalid",
                            "detail": "hash160 do witness pubkey não confere"}
                script_code = b"\x76\xa9\x14" + redeem[2:22] + b"\x88\xac"
                res = _ecdsa_check(tx, idx, script_code, value, sig, pub, True)
            elif rtype == "p2wsh":
                if not inp.witness:
                    return {"status": "invalid", "detail": "witness vazio"}
                witness_script = inp.witness[-1]
                if sha256(witness_script) != redeem[2:34]:
                    return {"status": "invalid",
                            "detail": "sha256 do witness script não confere"}
                res = evaluate_script(witness_script, inp.witness[:-1], tx,
                                      idx, value, True)
            else:
                res = evaluate_script(redeem, pushes[:-1], tx, idx, value,
                                      False)

        elif t in ("p2pkh", "p2pk", "multisig"):
            stack = script_pushes(inp.script_sig)
            res = evaluate_script(spk, stack, tx, idx, value, False)

        else:
            return {"status": "unsupported",
                    "detail": f"tipo de script não suportado: {type_label(t)}"}

        if notes:
            res.setdefault("notes", [])
            res["notes"] = notes + res.get("notes", [])
        return res

    except ValueError as exc:
        return {"status": "invalid", "detail": f"script inválido: {exc}"}
    except Exception as exc:  # nunca derruba a análise inteira
        return {"status": "invalid",
                "detail": f"erro ao validar ({type(exc).__name__}: {exc})"}


def infer_spk_from_witness(inp: TxIn):
    """Heurística: witness [sig, pubkey] -> scriptPubKey P2WPKH."""
    if len(inp.witness) == 2:
        sig, pub = inp.witness
        if 9 <= len(sig) <= 73 and decode_pubkey(pub) is not None:
            return b"\x00\x14" + hash160(pub)
    return None


# ------------------------------------------------------- prevouts ----

class PrevoutProvider:
    def __init__(self, api_base: str | None, offline: bool = False):
        self.api_base = api_base
        self.offline = offline or not api_base
        self.cache: dict[str, dict] = {}
        self.errors: dict[str, str] = {}

    def add_override(self, txid: str, vout: int, value: int,
                     spk: bytes | None) -> None:
        self.cache.setdefault(txid.lower(), {})[vout] = {
            "value": value, "spk": spk, "address": None, "type": None,
            "source": "manual",
        }

    def _fetch(self, txid: str) -> dict:
        if self.offline:
            raise RuntimeError("consulta de rede desativada")
        url = f"{self.api_base}/tx/{txid}"
        req = urllib.request.Request(
            url, headers={"User-Agent": f"hex_check/{__version__}"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        vouts = {}
        for pos, v in enumerate(data.get("vout", [])):
            raw = v.get("scriptpubkey") or ""
            vouts[v.get("n", pos)] = {
                "value": int(v.get("value", 0)),
                "spk": bytes.fromhex(raw),
                "address": v.get("scriptpubkey_address"),
                "type": v.get("scriptpubkey_type"),
                "source": "api",
            }
        return vouts

    def get(self, txid: str, vout: int):
        txid = txid.lower()
        if txid not in self.cache:
            if self.offline:
                return None
            try:
                self.cache[txid] = self._fetch(txid)
            except Exception as exc:
                self.errors[txid] = f"{type(exc).__name__}: {exc}"
                self.cache[txid] = {}
        return self.cache[txid].get(vout)

    @property
    def enabled(self) -> bool:
        return not self.offline


# -------------------------------------------------------- util html/json ----

EPILOG = """\
Formatos aceitos para o hex:
  argumento posicional, --file ARQ, ou stdin (pipe).

--prevout serve para informar manualmente os dados da moeda gasta (UTXO):
  --prevout TXID:VOUT=SATS
  --prevout TXID:VOUT=SATS:SCRIPT_PUBKEY_HEX

Exemplos:
  python3 hex_check.py 020000000001...
  python3 hex_check.py -f tx.hex
  cat tx.hex | python3 hex_check.py
  python3 hex_check.py --no-network 0200...
  python3 hex_check.py --network testnet 0200...
  python3 hex_check.py --prevout ab12...:0=100000 0200...

Sem --prevout e com rede habilitada, o script consulta a API pública
(mempool.space) para obter valor e scriptPubKey das UTXOs gastas.
"""


def build_parser():
    p = argparse.ArgumentParser(
        prog="hex_check.py",
        description="Decodifica, inspeciona e valida transações Bitcoin "
                    "a partir do hex bruto.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EPILOG,
    )
    p.add_argument("hex", nargs="*", metavar="HEX",
                   help="hex bruto da transação (pode ser entre aspas)")
    p.add_argument("-f", "--file", metavar="ARQ",
                   help="lê o hex de um arquivo (use - para stdin)")
    p.add_argument("--network", default="mainnet",
                   choices=list(NETWORKS.keys()),
                   help="rede usada para endereços e API (padrão: mainnet)")
    p.add_argument("--prevout", action="append", default=[], metavar="TXID:VOUT=SATS[:SPK]",
                   help="informa manualmente um prevout (repetível)")
    p.add_argument("--no-network", action="store_true",
                   help="não consulta APIs; usa apenas --prevout")
    p.add_argument("--json", action="store_true",
                   help="emite a análise em JSON")
    p.add_argument("--no-color", action="store_true",
                   help="desativa cores ANSI")
    p.add_argument("--version", action="version",
                   version=f"hex_check.py {__version__}")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="mostra detalhes adicionais (pushes, witness)")
    return p


def read_hex_input(args):
    raw = None
    if args.file:
        if args.file == "-":
            raw = sys.stdin.read()
        else:
            try:
                with open(args.file, "r", encoding="utf-8",
                          errors="ignore") as fh:
                    raw = fh.read()
            except OSError as exc:
                print(f"Erro ao ler arquivo: {exc}", file=sys.stderr)
                sys.exit(1)
    elif args.hex:
        raw = " ".join(args.hex)
    elif not sys.stdin.isatty():
        raw = sys.stdin.read()
    else:
        try:
            raw = input("Cole o hex da transação: ")
        except (EOFError, KeyboardInterrupt):
            print()
            return None
    if raw is None:
        return None
    cleaned = "".join(raw.split())
    if cleaned[:2].lower() == "0x":
        cleaned = cleaned[2:]
    if not cleaned:
        return None
    if len(cleaned) % 2 or any(c not in "0123456789abcdefABCDEF"
                               for c in cleaned):
        print("Erro: o conteúdo informado não é um hex válido.",
              file=sys.stderr)
        sys.exit(1)
    return cleaned.lower()


def parse_prevouts(overrides):
    out = []
    for s in overrides or []:
        try:
            if "=" in s:
                left, right = s.split("=", 1)
            else:
                raise ValueError("falta '=' (TXID:VOUT=SATS[:SPK_HEX])")
            if ":" not in left:
                raise ValueError("formato TXID:VOUT")
            txid, vs = left.split(":", 1)
            if len(txid) != 64 or any(c not in "0123456789abcdefABCDEF"
                                      for c in txid):
                raise ValueError("txid deve ter 64 caracteres hex")
            vout = int(vs)
            if vout < 0:
                raise ValueError("vout não pode ser negativo")
            spk = None
            if ":" in right:
                vals, spks = right.split(":", 1)
                if spks.strip():
                    spk = bytes.fromhex(spks.strip())
                sats = int(vals.strip())
            else:
                sats = int(right.strip())
            out.append((txid.lower(), vout, sats, spk))
        except Exception as exc:
            print(f"Aviso: --prevout inválido '{s}': {exc}", file=sys.stderr)
    return out


# ------------------------------------------------------------ display ----

def hr(title):
    print()
    print(bold(cyan("=" * 78)))
    print(bold(cyan(f"  {title}")))
    print(bold(cyan("=" * 78)))


def show_transaction(tx: Transaction, warnings):
    hr("TRANSAÇÃO BRUTA")
    print(f"  txid:        {bold(tx.txid)}")
    if tx.segwit:
        print(f"  wtxid:       {bold(tx.wtxid)}")
    print(f"  Versão:      {tx.version}")
    print(f"  SegWit:      {'sim' if tx.segwit else 'não'}")
    if tx.segwit:
        print(f"  Marker/flag: 00{tx.flag:02x}")
    print(f"  Locktime:    {fmt_locktime(tx.locktime)}")
    print(f"  Coinbase:    {'sim' if tx.is_coinbase else 'não'}")
    print(f"  RBF:         {'sim' if tx.rbf else 'não'}")
    print(f"  Tamanho:     {tx.size} bytes (base {tx.base_size})")
    print(f"  Peso:        {tx.weight} wu")
    print(f"  vSize:       {tx.vsize} vB")
    print(f"  Entradas:    {len(tx.inputs)}")
    print(f"  Saídas:      {len(tx.outputs)}")
    if warnings:
        print()
        print(yellow("  AVISOS DE PARSING:"))
        for w in warnings:
            print(yellow(f"    • {w}"))


def show_inputs(tx: Transaction, prevouts_res, provider: PrevoutProvider,
                network: str, verbose: bool):
    hr("ENTRADAS (de onde vêm)")
    if tx.is_coinbase:
        print("  [COINBASE] Sem dados de UTXO gasto (miner reward).")
        print("  ScriptSig:", hexstr(tx.inputs[0].script_sig) or "(vazio)")
        if tx.inputs[0].witness:
            print("  Witness:", "[", ", ".join(hexstr(w, 72)
                                                     for w in tx.inputs[0].witness), "]")
        return
    total_in = 0
    known_in = 0
    for i, inp in enumerate(tx.inputs):
        p = prevouts_res[i]
        print()
        print(bold(f"  [{i}] {inp.outpoint}"))
        print(f"      Sequence: {inp.sequence:08x} ({inp.sequence})")
        if p and p.get("value") is not None:
            val = p["value"]
            total_in += val
            known_in += 1
            print(f"      Valor:    {fmt_amount(val)}")
        else:
            print(yellow("      Valor:    desconhecido"))
        if p and p.get("spk"):
            spk = p["spk"]
            t = classify_script(spk)
            addr = script_address(spk, network)
            print(f"      Tipo:     {type_label(t)}")
            print(f"      ScriptPubKey: {hexstr(spk, 64)}")
            if addr:
                print(f"      Endereço: {bold(addr)}")
            else:
                print(f"      Endereço: {dim('(não derivável)')}")
        else:
            spk2 = infer_spk_from_witness(inp)
            if spk2:
                t2 = classify_script(spk2)
                addr2 = script_address(spk2, network)
                print(f"      Tipo:     {type_label(t2)} (inferido por witness)")
                print(f"      ScriptPubKey: {hexstr(spk2, 64)}")
                if addr2:
                    print(f"      Endereço: {bold(addr2)}")
            else:
                print(yellow("      ScriptPubKey/Endereço: desconhecido"))
        if inp.script_sig:
            print(f"      ScriptSig: {hexstr(inp.script_sig, 80)}")
            if verbose:
                try:
                    pushes = script_pushes(inp.script_sig)
                    for j, ps in enumerate(pushes):
                        print(f"        [{j}] len={len(ps)} 0x{hexstr(ps, 70)}")
                except Exception as exc:
                    print(f"        {dim('(erro ao dissecar: ' + str(exc) + ')')}")
        else:
            print("      ScriptSig: (vazio)")
        if inp.witness:
            print(f"      Witness:   [{len(inp.witness)} item(ns)]")
            for j, w in enumerate(inp.witness):
                lim = None if verbose else 72
                print(f"        [{j}] len={len(w)} 0x{hexstr(w, lim)}")
        else:
            print("      Witness:   (vazio)")
    print()
    if known_in == len(tx.inputs):
        print(bold(f"  Soma entradas: {fmt_amount(total_in)}"))
    elif known_in:
        print(bold(f"  Soma entradas (parcial): {fmt_amount(total_in)}"))
    else:
        print(yellow("  Soma entradas: não é possível calcular (prevouts desconhecidos)"))
    if provider.enabled and provider.errors:
        print()
        print(yellow("  Falhas ao buscar prevouts:"))
        for txid, err in provider.errors.items():
            print(yellow(f"    • {txid}: {err}"))
    elif not provider.enabled:
        print()
        print(dim("  Rede desativada; prevouts só com --prevout ou já em cache."))


def show_outputs(tx: Transaction, network: str):
    hr("SAÍDAS (para onde vão)")
    total_out = 0
    for i, out in enumerate(tx.outputs):
        print()
        print(bold(f"  [{i}]"))
        total_out += out.value
        print(f"      Valor:        {fmt_amount(out.value)}")
        spk = out.script_pubkey
        t = classify_script(spk)
        addr = script_address(spk, network)
        print(f"      Tipo:         {type_label(t)}")
        print(f"      ScriptPubKey: {hexstr(spk, 64)}")
        print(f"      Script:       {disassemble(spk, 80)}")
        if t == "op_return":
            payload = spk[1:]
            pushed, _ = _read_push(spk, 1)
            if pushed is not None:
                payload = pushed
            print(f"      Dados:        {hexstr(payload, 120)}")
            if payload and all(32 <= c < 127 for c in payload):
                print(f'      Texto:        "{payload.decode("ascii")}"')
        if addr:
            print(f"      Endereço:     {bold(addr)}")
        elif t != "op_return":
            print(f"      Endereço:     {dim('(não derivável)')}")
    print()
    print(bold(f"  Soma saídas: {fmt_amount(total_out)}"))


def compute_fee(tx: Transaction, prevouts_res):
    """Retorna a taxa em sats, ou None se faltar algum prevout."""
    if tx.is_coinbase or len(prevouts_res) != len(tx.inputs):
        return None
    total_in = 0
    for p in prevouts_res:
        if not p or p.get("value") is None:
            return None
        total_in += p["value"]
    return total_in - sum(o.value for o in tx.outputs)


def show_fee(tx: Transaction, prevouts_res):
    hr("TAXA (FEE)")
    if tx.is_coinbase:
        print(dim("  Transação coinbase: taxa não se aplica."))
        return None
    total_out = sum(o.value for o in tx.outputs)
    known = sum(1 for p in prevouts_res
                if p and p.get("value") is not None)
    total_in = sum(p["value"] for p in prevouts_res
                   if p and p.get("value") is not None)
    if known < len(tx.inputs):
        print(yellow(f"  Não é possível calcular a taxa: {len(tx.inputs) - known} "
                     f"de {len(tx.inputs)} prevout(s) sem valor conhecido."))
        if known:
            print(dim(f"  Soma parcial das entradas conhecidas: "
                      f"{fmt_amount(total_in)}"))
        print(dim("  Use --prevout TXID:VOUT=SATS[:SPK_HEX] ou habilite a rede."))
        return None
    fee = total_in - total_out
    print(f"  Total entradas: {fmt_amount(total_in)}")
    print(f"  Total saídas:   {fmt_amount(total_out)}")
    if fee < 0:
        print(red(f"  Taxa: {fmt_amount(fee)} (NEGATIVA — saídas excedem entradas)"))
        return fee
    if fee == 0:
        print(yellow(f"  Taxa: {fmt_amount(fee)} (zero)"))
    else:
        print(green(f"  Taxa: {fmt_amount(fee)}"))
    print(f"  Taxa por vB:    {fee / tx.vsize:.2f} sat/vB")
    print(f"  Taxa por kvB:   {fee * 1000 / tx.vsize:.0f} sat/kvB")
    return fee


def structural_checks(tx: Transaction, prevouts_res, fee):
    """Checagens estruturais independentes de assinatura."""
    errors = []
    warnings = []
    if not tx.inputs:
        errors.append("transação sem entradas")
    if not tx.outputs:
        errors.append("transação sem saídas")

    seen = set()
    for idx, inp in enumerate(tx.inputs):
        if inp.outpoint in seen:
            errors.append(f"entrada {idx}: outpoint duplicado ({inp.outpoint})")
        seen.add(inp.outpoint)

    total_out = sum(o.value for o in tx.outputs)
    if total_out > MAX_MONEY:
        errors.append("soma das saídas excede o limite de 21 milhões de BTC")
    for idx, out in enumerate(tx.outputs):
        if out.value > MAX_MONEY:
            errors.append(f"saída {idx}: valor acima do limite de 21 milhões de BTC")

    if fee is not None and fee < 0:
        errors.append("saídas maiores que as entradas (taxa negativa)")

    if tx.is_coinbase:
        cs = tx.inputs[0].script_sig if tx.inputs else b""
        if not (2 <= len(cs) <= 100):
            warnings.append("scriptSig de coinbase fora do intervalo 2..100 bytes")
    else:
        for idx, inp in enumerate(tx.inputs):
            zeros = inp.prev_txid == b"\x00" * 32
            if zeros and inp.prev_vout != 0xFFFFFFFF:
                errors.append(f"entrada {idx}: prevout nulo inválido")
            if inp.prev_vout == 0xFFFFFFFF and not zeros:
                warnings.append(f"entrada {idx}: vout 0xffffffff fora de coinbase")

    for idx, inp in enumerate(tx.inputs):
        p = prevouts_res[idx] if idx < len(prevouts_res) else None
        spk = p.get("spk") if p else None
        if not spk:
            continue
        stype = classify_script(spk)
        if stype in ("p2wpkh", "p2wsh") and inp.script_sig:
            warnings.append(f"entrada {idx}: scriptSig não vazio em SegWit nativo")
        if stype == "p2sh":
            if not inp.script_sig:
                warnings.append(f"entrada {idx}: P2SH sem redeem script no scriptSig")
            else:
                try:
                    pushes = script_pushes(inp.script_sig)
                    rt = classify_script(pushes[-1])
                    if rt in ("p2wpkh", "p2wsh") and len(pushes) != 1:
                        warnings.append(f"entrada {idx}: scriptSig de P2SH "
                                        "aninhado deveria ter apenas 1 push")
                except ValueError:
                    pass

    if not tx.segwit and any(i.witness for i in tx.inputs):
        warnings.append("witness presente, mas marker/flag ausente")

    if fee is not None and fee >= 0 and tx.vsize:
        rate = fee / tx.vsize
        if rate < 1:
            warnings.append(f"taxa muito baixa: {rate:.2f} sat/vB")
    return errors, warnings


def show_structure(errors, warnings):
    hr("VALIDAÇÃO ESTRUTURAL")
    if not errors and not warnings:
        print(green("  Nenhum problema estrutural detectado."))
        return
    for e in errors:
        print(red(f"  ✗ {e}"))
    for w in warnings:
        print(yellow(f"  ! {w}"))


def compute_verification(tx: Transaction, prevouts_res):
    """Retorna (lista de resultados por entrada, resumo textual)."""
    if tx.is_coinbase:
        return [], "n/a"
    results = [verify_input(tx, i, prevouts_res[i], prevouts_res)
               for i in range(len(tx.inputs))]
    valid = [r for r in results if r["status"] == "valid"]
    invalid = [r for r in results if r["status"] == "invalid"]
    unknown = [r for r in results if r["status"] == "unknown"]
    unsupported = [r for r in results if r["status"] == "unsupported"]
    if not results:
        summary = "vazia"
    elif invalid:
        summary = red("INVÁLIDA")
    elif unknown and not valid:
        summary = yellow("INDETERMINADA")
    elif valid and not unknown and not unsupported:
        summary = green("VÁLIDA")
    elif valid:
        summary = yellow("PARCIALMENTE VERIFICADA")
    else:
        summary = yellow("INDETERMINADA")
    return results, summary


def show_verification(tx: Transaction, prevouts_res, verbose: bool):
    hr("VERIFICAÇÃO DE ASSINATURAS")
    if tx.is_coinbase:
        print("  [COINBASE] Sem verificações de assinatura.")
        return [], "n/a"
    results, summary = compute_verification(tx, prevouts_res)
    for i, res in enumerate(results):
        print()
        print(bold(f"  Entrada [{i}]"))
        st = res["status"]
        if st == "valid":
            print(green("    VEREDICTO: VÁLIDA"))
            if res.get("scheme"):
                print(f"    Esquema:   {res['scheme']}")
            if res.get("sighash") is not None:
                print(f"    Sighash:   0x{res['sighash']:02x} "
                      f"({_sighash_name(res['sighash'])})")
            if res.get("detail") and res["detail"] != "key path":
                print(f"    Detalhe:   {res['detail']}")
        elif st == "invalid":
            print(red("    VEREDICTO: INVÁLIDA"))
            if res.get("detail"):
                print(f"    Motivo:    {res['detail']}")
            if res.get("scheme"):
                print(f"    Esquema:   {res['scheme']}")
            if res.get("sighash") is not None:
                print(f"    Sighash:   0x{res['sighash']:02x} "
                      f"({_sighash_name(res['sighash'])})")
        elif st == "unknown":
            print(yellow("    VEREDICTO: INDETERMINADA"))
            if res.get("detail"):
                print(f"    Motivo:    {res['detail']}")
        elif st == "n/a":
            print(dim("    VEREDICTO: N/A"))
            if res.get("detail"):
                print(f"    Motivo:    {res['detail']}")
        else:
            label = "NÃO SUPORTADO" if st == "unsupported" else st.upper()
            print(yellow(f"    VEREDICTO: {label}"))
            if res.get("detail"):
                print(f"    Motivo:    {res['detail']}")
        for n in res.get("notes", []):
            print(dim(f"    Nota:      {n}"))

    valid = [r for r in results if r["status"] == "valid"]
    invalid = [r for r in results if r["status"] == "invalid"]
    unknown = [r for r in results if r["status"] == "unknown"]
    unsupported = [r for r in results if r["status"] == "unsupported"]
    print()
    print(bold("  RESUMO:"))
    print(f"    Entradas: {len(results)}")
    print(green(f"    Válidas: {len(valid)}"))
    print(red(f"    Inválidas: {len(invalid)}"))
    print(yellow(f"    Indeterminadas: {len(unknown)}"))
    if unsupported:
        print(dim(f"    Não suportadas: {len(unsupported)}"))
    return results, summary


def to_json(tx: Transaction, prevouts_res, ver_res, fee, network: str,
            warnings, struct_errors, struct_warnings, ver_summary,
            provider_errors):
    def prevout_dict(p):
        if not p:
            return None
        spk = p.get("spk")
        return {
            "value_sats": p.get("value"),
            "value_btc": (fmt_btc(p["value"])
                          if p.get("value") is not None else None),
            "script_pubkey": spk.hex() if spk else None,
            "address": script_address(spk, network) if spk else None,
            "type": type_label(classify_script(spk)) if spk else None,
            "source": p.get("source"),
        }

    ins = []
    for i, inp in enumerate(tx.inputs):
        ins.append({
            "index": i,
            "txid": inp.prev_txid_hex,
            "vout": inp.prev_vout,
            "outpoint": inp.outpoint,
            "sequence": inp.sequence,
            "script_sig": inp.script_sig.hex(),
            "script_sig_asm": disassemble(inp.script_sig),
            "witness": [w.hex() for w in inp.witness],
            "prevout": prevout_dict(prevouts_res[i]
                                    if i < len(prevouts_res) else None),
            "signature": ver_res[i] if i < len(ver_res) else None,
        })

    outs = []
    for i, out in enumerate(tx.outputs):
        spk = out.script_pubkey
        stype = classify_script(spk)
        outs.append({
            "index": i,
            "value_sats": out.value,
            "value_btc": fmt_btc(out.value),
            "script_pubkey": spk.hex(),
            "script_asm": disassemble(spk),
            "address": script_address(spk, network),
            "type": type_label(stype),
            "is_op_return": stype == "op_return",
        })

    if len(prevouts_res) == len(tx.inputs) and all(
            p and p.get("value") is not None for p in prevouts_res):
        total_in = sum(p["value"] for p in prevouts_res)
    else:
        total_in = None
    total_out = sum(o.value for o in tx.outputs)

    if struct_errors:
        verdict = "INVÁLIDA (estrutura)"
    elif ver_summary == "VÁLIDA":
        verdict = "VÁLIDA"
    elif ver_summary == "INVÁLIDA":
        verdict = "INVÁLIDA (assinatura)"
    elif ver_summary == "n/a":
        verdict = "COINBASE"
    else:
        verdict = "INDETERMINADA"

    return {
        "script_version": __version__,
        "network": network,
        "txid": tx.txid,
        "wtxid": tx.wtxid if tx.segwit else None,
        "segwit": tx.segwit,
        "version": tx.version,
        "locktime": tx.locktime,
        "locktime_formatted": fmt_locktime(tx.locktime),
        "size": tx.size,
        "base_size": tx.base_size,
        "weight": tx.weight,
        "vsize": tx.vsize,
        "is_coinbase": tx.is_coinbase,
        "rbf": tx.rbf,
        "inputs": ins,
        "outputs": outs,
        "total_input_sats": total_in,
        "total_output_sats": total_out,
        "fee_sats": fee,
        "fee_btc": fmt_btc(fee) if fee is not None else None,
        "fee_sat_vb": fee / tx.vsize if fee is not None else None,
        "verification_summary": ver_summary,
        "verdict": verdict,
        "parse_warnings": warnings,
        "structural_errors": struct_errors,
        "structural_warnings": struct_warnings,
        "provider_errors": provider_errors,
    }


def main():
    global _COLOR
    parser = build_parser()
    args = parser.parse_args()
    hexstripped = read_hex_input(args)
    if hexstripped is None:
        parser.print_help(sys.stderr)
        sys.exit(1)
    _COLOR = (sys.stdout.isatty() and not args.no_color
              and "NO_COLOR" not in os.environ)
    try:
        raw = bytes.fromhex(hexstripped)
    except ValueError as exc:
        print(f"Erro: hex inválido - {exc}", file=sys.stderr)
        sys.exit(1)
    try:
        tx, warnings = parse_tx(raw)
    except Exception as exc:
        print(f"Erro ao decodificar transação: {exc}", file=sys.stderr)
        sys.exit(1)

    net = NETWORKS[args.network]
    provider = PrevoutProvider(net["api"], offline=args.no_network)
    for ov in parse_prevouts(args.prevout):
        txid, vout, sats, spk = ov
        provider.add_override(txid, vout, sats, spk)

    prevouts_res = []
    if not tx.is_coinbase:
        for inp in tx.inputs:
            p = provider.get(inp.prev_txid_hex, inp.prev_vout)
            if tx.segwit and (p is None or p.get("spk") is None):
                spk2 = infer_spk_from_witness(inp)
                if spk2:
                    if p is None:
                        p = {"value": None, "spk": spk2, "address": None,
                             "type": None, "source": "infer_witness"}
                    else:
                        p = {**p, "spk": spk2,
                             "source": p.get("source", "") + "+infer"}
            prevouts_res.append(p)
    else:
        prevouts_res = [None]

    fee = compute_fee(tx, prevouts_res)
    struct_errors, struct_warnings = structural_checks(tx, prevouts_res, fee)

    if args.json:
        ver_res, ver_summary = compute_verification(tx, prevouts_res)
        payload = to_json(tx, prevouts_res, ver_res, fee, args.network,
                          warnings, struct_errors, struct_warnings,
                          ver_summary, provider.errors)
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    show_transaction(tx, warnings)
    show_inputs(tx, prevouts_res, provider, args.network, args.verbose)
    show_outputs(tx, args.network)
    show_fee(tx, prevouts_res)
    show_structure(struct_errors, struct_warnings)
    ver_res, ver_summary = show_verification(tx, prevouts_res, args.verbose)

    hr("VEREDITO GERAL")
    if struct_errors:
        print(red("  INVÁLIDA — há erro(s) estrutural(is):"))
        for err in struct_errors:
            print(red(f"    • {err}"))
        print(f"  Assinaturas: {ver_summary}")
    elif tx.is_coinbase:
        print(green("  COINBASE — sem assinaturas a verificar."))
    else:
        print(f"  {ver_summary}")
    print()
    if fee is not None:
        if fee >= 0:
            print(f"  Taxa: {fmt_amount(fee)} | {fee / tx.vsize:.2f} sat/vB")
        else:
            print(red(f"  Taxa: {fmt_amount(fee)} (inválida)"))
    print(f"  Rede: {args.network}")


if __name__ == "__main__":
    main()
