These projects are intended solely for educational purposes to help individuals understand the principles of cryptography and blockchain technology. It is important to recognize that attempting to generate Bitcoin wallets in the hope of randomly finding one with a balance is not a feasible strategy. This same logic applies to any tool that tries to work in any way the same as this.

The number of possible Bitcoin wallet combinations exceeds 76 trillion, making the odds of discovering an active wallet astronomically low. To put it into perspective, you are statistically far more likely to win the lottery every day for the rest of your life than to recover even a single wallet with funds—even over the course of a decade.


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

![image](https://github.com/user-attachments/assets/b6c54303-9905-429b-b349-85563ebff81a)
