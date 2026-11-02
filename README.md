# hex-check

**Inspetor e validador de transações Bitcoin a partir do hex bruto.**

O `hex_check.py` decodifica uma transação Bitcoin crua (raw hex), mostra de onde vêm e para onde vão os fundos, calcula a taxa e **verifica criptograficamente as assinaturas** — tudo em Python puro, sem dependências externas.

```
Entrada:  8.943 sats  bc1qhvhj3lwcmsp5zpx9twwyj9vlsa4srr4sh632c8
Saída:    8.723 sats  bc1qv03q2u4vj9ckn4zzcmlpx7z3vy3khflulahe5m
Taxa:     220 sats    (2,00 sat/vB)
Veredito: TRANSAÇÃO VÁLIDA (ECDSA BIP143, SIGHASH_ALL)
```

---

## Destaques

- Decodifica versão, entradas, saídas, witnesses, sequence, locktime, RBF e coinbase;
- Calcula **txid**, **wtxid**, tamanho, peso (weight) e **vsize**;
- Identifica e decodifica scripts: P2PKH, P2SH, P2WPKH, P2WSH, P2TR, P2PK, multisig e OP_RETURN;
- Mostra **endereços de origem e destino**, valores e tipos de script;
- Calcula **taxa total**, **sat/vB** e **sat/kvB**;
- Valida assinaturas:
  - **ECDSA legacy** — P2PK, P2PKH, P2SH e multisig;
  - **ECDSA BIP143** — P2WPKH, P2SH-P2WPKH, P2WSH e multisig em witness;
  - **Schnorr BIP340/BIP341** — P2TR (Taproot, key path);
- Busca os prevouts automaticamente via [mempool.space](https://mempool.space) ou aceita dados manuais com `--prevout`;
- Faz checagens estruturais (outpoints duplicados, taxa negativa, valores acima de 21 milhões de BTC, scriptSig em SegWit nativo etc.);
- Saída colorida no terminal, modo `--json` e suporte a mainnet, testnet, signet e regtest;
- **Nenhuma dependência externa** — só a biblioteca padrão do Python.

---

## Requisitos

- Python **3.9+** (testado em Python 3.14);
- Nenhum `pip install` necessário.

---

## Instalação

```bash
git clone https://github.com/tadeuc-dev/hex-check.git
cd hex-check
chmod +x hex_check.py
```

---

## Uso

```bash
# hex como argumento
python3 hex_check.py <HEX>

# arquivo ou stdin
python3 hex_check.py -f tx.hex
cat tx.hex | python3 hex_check.py

# sem consultar a rede (usa prevouts informados manualmente)
python3 hex_check.py --no-network --prevout TXID:VOUT=SATS <HEX>

# outras redes
python3 hex_check.py --network testnet <HEX>

# saída JSON / detalhes
python3 hex_check.py --json <HEX>
python3 hex_check.py --verbose <HEX>
```

Se for executado sem argumentos em um terminal, o script pede o hex interativamente.

### Opções

| Opção | Descrição |
| --- | --- |
| `HEX` | Hex bruto da transação (pode ser dividido em vários argumentos) |
| `-f, --file ARQ` | Lê o hex de um arquivo (`-` para stdin) |
| `--network mainnet\|testnet\|signet\|regtest` | Rede usada para endereços e API (padrão: `mainnet`) |
| `--prevout TXID:VOUT=SATS[:SPK]` | Informa manualmente um prevout (repetível) |
| `--no-network` | Não consulta APIs; usa apenas `--prevout` |
| `--json` | Emite a análise completa em JSON |
| `--verbose, -v` | Mostra pushes de script e witness completos |
| `--no-color` | Desativa cores ANSI |
| `--version` | Mostra a versão |
| `-h, --help` | Ajuda |

### Formato do `--prevout`

```
--prevout TXID:VOUT=SATS
--prevout TXID:VOUT=SATS:SCRIPT_PUBKEY_HEX
```

Exemplo:

```bash
python3 hex_check.py --no-network \
  --prevout aec5591a5a313b642fecf1560d0121a48dae9abf6ca414edce8f2202020ba646:0=8943 \
  0200000000010146a60b...
```

Se o `SCRIPT_PUBKEY_HEX` for omitido e a entrada for P2WPKH, o script infere o `scriptPubKey` a partir da chave pública do witness.

---

## Exemplo de saída

```text
==============================================================================
  TRANSAÇÃO BRUTA
==============================================================================
  txid:        c5f5d655665d1a408eb6360c4bacfc19bc6c380b729b8bd1831d5f9d756a5d3e
  wtxid:       859b2411a4496395c27f2081df2b169f192847810d69a2e305fa466ca232a237
  Versão:      2
  SegWit:      sim
  Marker/flag: 0001
  Locktime:    0 (desativado)
  Coinbase:    não
  RBF:         sim
  Tamanho:     191 bytes (base 82)
  Peso:        437 wu
  vSize:       110 vB
  Entradas:    1
  Saídas:      1

==============================================================================
  ENTRADAS (de onde vêm)
==============================================================================

  [0] aec5591a5a313b642fecf1560d0121a48dae9abf6ca414edce8f2202020ba646:0
      Sequence: fffffffd (4294967293)
      Valor:    0.00008943 BTC (8.943 sats)
      Tipo:     P2WPKH (SegWit v0)
      ScriptPubKey: 0014bb2f28fdd8dc034104c55b9c49159f876b018eb0
      Endereço: bc1qhvhj3lwcmsp5zpx9twwyj9vlsa4srr4sh632c8
      ScriptSig: (vazio)
      Witness:   [2 item(ns)]

==============================================================================
  SAÍDAS (para onde vão)
==============================================================================

  [0]
      Valor:        0.00008723 BTC (8.723 sats)
      Tipo:         P2WPKH (SegWit v0)
      ScriptPubKey: 001463e20572ac917169d442c6fe13785161236ba7fc
      Script:       OP_0 PUSH[20] 0x63e20572ac917169d442c6fe13785161236ba7fc
      Endereço:     bc1qv03q2u4vj9ckn4zzcmlpx7z3vy3khflulahe5m

==============================================================================
  TAXA (FEE)
==============================================================================
  Total entradas: 0.00008943 BTC (8.943 sats)
  Total saídas:   0.00008723 BTC (8.723 sats)
  Taxa: 0.00000220 BTC (220 sats)
  Taxa por vB:    2.00 sat/vB
  Taxa por kvB:   2000 sat/kvB

==============================================================================
  VERIFICAÇÃO DE ASSINATURAS
==============================================================================

  Entrada [0]
    VEREDICTO: VÁLIDA
    Esquema:   ECDSA (BIP143)
    Sighash:   0x01 (SIGHASH_ALL)

==============================================================================
  VEREDITO GERAL
==============================================================================
  VÁLIDA

  Taxa: 0.00000220 BTC (220 sats) | 2.00 sat/vB
  Rede: mainnet
```

---

## Como funciona

1. **Parsing** — leitura binária com validação de limites e varints canônicos (BIP144 para SegWit);
2. **Hashes** — `txid` = SHA256d da serialização sem witness; `wtxid` = SHA256d da serialização completa; weight/vsize conforme BIP141;
3. **Sighash**:
   - algoritmo legacy (SIGHASH_ALL/NONE/SINGLE e ANYONECANPAY);
   - BIP143 para SegWit v0;
   - BIP341 para Taproot, incluindo o epoch `0x00` no tagged hash `TapSighash`;
4. **Assinaturas** — ECDSA sobre secp256k1 e Schnorr BIP340 implementados em Python puro, com verificação de DER, pubkeys comprimidas/não comprimidas e chaves x-only;
5. **Prevouts** — valores e `scriptPubKey` das UTXOs gastas são obtidos na API da mempool.space (ou via `--prevout`). Eles são necessários para a taxa e para validar assinaturas SegWit/Taproot.

---

## Tipos de script suportados na verificação

| Tipo | Verificação de assinatura |
| --- | --- |
| P2PK | ✅ ECDSA legacy |
| P2PKH | ✅ ECDSA legacy |
| P2SH (legacy) | ✅ ECDSA legacy, incluindo multisig |
| P2SH-P2WPKH | ✅ ECDSA BIP143 |
| P2SH-P2WSH | ✅ ECDSA BIP143 (scripts padrão/multisig) |
| P2WPKH | ✅ ECDSA BIP143 |
| P2WSH | ✅ ECDSA BIP143 (P2PK/P2PKH/multisig) |
| P2TR (key path) | ✅ Schnorr BIP340/BIP341 |
| P2TR (script path / tapscript) | ⚠️ Reconhecido, mas não verificado |
| OP_RETURN | ✅ Decodificado (sem assinatura) |

---

## Vereditos

| Veredito | Significado |
| --- | --- |
| **VÁLIDA** | Estrutura e todas as assinaturas verificadas com sucesso |
| **INVÁLIDA** | Assinatura incorreta, script inconsistente ou erro estrutural |
| **INDETERMINADA** | Faltam prevouts (valor/scriptPubKey) para concluir a verificação |
| **PARCIALMENTE VERIFICADA** | Algumas entradas verificadas; outras não suportadas ou sem dados |
| **NÃO SUPORTADO** | Tipo de script reconhecido, mas sem verificador implementado |
| **COINBASE** | Transação de coinbase: não há assinaturas a verificar |

---

## Limitações

- A verificação é **estrutural + de assinaturas**. Não substitui um nó completo: não consulta a UTXO set, não valida maturidade de coinbase, limites de sigops, politicas de relay/mempool etc.
- **Taproot script path (tapscript)** é reconhecido, mas a assinatura não é validada.
- Para calcular taxa e validar assinaturas SegWit/Taproot é necessário conhecer os prevouts. Sem rede e sem `--prevout`, o resultado fica **INDETERMINADO**.
- Ao usar a rede, os txids dos prevouts são enviados à API pública da mempool.space.

---

## Testes

Além dos vetores oficiais BIP340 e BIP341, o verificador foi testado contra transações reais da mainnet envolvendo P2PKH, P2SH, P2WPKH, P2WSH, multisig e P2TR (key path), com resultados válidos.

---

## Licença

MIT — veja [LICENSE](LICENSE).
