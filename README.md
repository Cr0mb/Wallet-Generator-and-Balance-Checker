# Wallet-Generator-and-Balance-Checker
This Python script generates wallets for Ethereum (ETH), Bitcoin (BTC), and Toncoin (TON) using random mnemonic phrases. It also fetches the current balance for each wallet type and displays them.


## Features
- Generates Wallets for ETH, BTC, and TON:

  - Ethereum (ETH) wallet generation uses BIP44 standard.
  - Bitcoin (BTC) wallets support P2PKH, P2SH-P2WPKH, and P2WPKH formats.
  - Toncoin (TON) wallet generation uses TON SDK.
  - Fetches Wallet Balances:

  - Ethereum balance is fetched using the BlockCypher API.
  - Bitcoin balance is fetched from Blockstream and Blockchair APIs.
  - Toncoin balance is fetched from TON Center API.
- Mnemonic Generation:

The script generates a random mnemonic phrase (12, 15, 18, 21, or 24 words).

## Requirements
- Python 3.x
```
pip install ecdsa hashlib base58 requests bech32 mnemonic bip-utils eth-utils colorama pyfiglet py-ton
```

