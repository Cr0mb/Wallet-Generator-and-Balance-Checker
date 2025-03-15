import os
import ecdsa
import hashlib
import base58
import json
import time
import requests
import bech32
import logging
import secrets
from mnemonic import Mnemonic
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
from eth_utils import to_checksum_address
from colorama import Fore, Style, init
import random
from concurrent.futures import ThreadPoolExecutor
from tonsdk.contract.wallet import Wallets, WalletVersionEnum
import pyfiglet

init(autoreset=True)

logging.basicConfig(filename="wallet_generator.log", level=logging.INFO, format="%(asctime)s - %(message)s")

ETH_BLOCKCYPHER_API_URL = "https://api.blockcypher.com/v1/eth/main/addrs/{}"
ETH_ETHPLORER_API_URL = "https://api.ethplorer.io/getAddressInfo/{}?apiKey=freekey"
BTC_API_URLS = {
    "blockstream": "https://blockstream.info/api/address/",
    "blockchair": "https://api.blockchair.com/bitcoin/dashboards/address/"
}
TON_API_URL = 'https://toncenter.com/api/v2/getAddressInformation?address={}'

OUTPUT_FILE = "wallets_with_balance.txt"

def log_event(message):
    print(Fore.YELLOW + message)
    logging.info(message)

def get_balance(address, blockchain):
    try:
        if blockchain == 'ETH':
            response = requests.get(ETH_BLOCKCYPHER_API_URL.format(address), timeout=10)
            return response.json().get("balance", 0) / 1e18
        elif blockchain == 'BTC':
            for name, url in BTC_API_URLS.items():
                response = requests.get(f"{url}{address}", timeout=10)
                data = response.json()
                if name == "blockchair":
                    return data.get('data', {}).get(address, {}).get('address', {}).get('balance', 0) / 1e8
                return data.get('chain_stats', {}).get('funded_txo_sum', 0) / 1e8
        elif blockchain == 'TON':
            response = requests.get(TON_API_URL.format(address), timeout=10)
            data = response.json()
            if data.get("ok"):
                return data['result']['balance'] / 10**9
            else:
                log_event(f"Error fetching TON balance for {address}: {data.get('result', 'Unknown error')}")
    except Exception as e:
        log_event(f"Error fetching {blockchain} balance for {address}: {e}")
    return None

def generate_mnemonic():
    strength_mapping = {12: 128, 15: 160, 18: 192, 21: 224, 24: 256}
    mnemonic_length = random.choice([12, 15, 18, 21, 24])
    strength = strength_mapping[mnemonic_length]
    return Mnemonic("english").generate(strength)

def generate_wallets(seed):
    wallets = {}

    # Generate Ethereum Wallet
    seed_bytes = Bip39SeedGenerator(seed).Generate()
    bip44_eth = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM)
    eth_address = bip44_eth.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0).PublicKey().ToAddress()
    private_key = bip44_eth.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0).PrivateKey().Raw().ToHex()
    wallets["eth"] = {"address": to_checksum_address(eth_address), "private_key": private_key, "blockchain": "ETH"}

    # Generate Bitcoin Wallets
    private_key = os.urandom(32)
    public_key = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1).get_verifying_key().to_string()
    ripemd160_pk = hashlib.new('ripemd160', hashlib.sha256(public_key).digest()).digest()

    # P2PKH (Legacy)
    p2pkh_address = base58.b58encode_check(b'\x00' + ripemd160_pk).decode('utf-8')

    # P2SH-P2WPKH (Wrapped SegWit)
    p2sh_p2wpkh_address = base58.b58encode_check(b'\x05' + ripemd160_pk).decode('utf-8')

    # P2WPKH (Native SegWit)
    p2wpkh_address = bech32.encode("bc", 0, ripemd160_pk)

    wallets["btc"] = {
        "p2pkh": p2pkh_address,
        "p2sh_p2wpkh": p2sh_p2wpkh_address,
        "p2wpkh": p2wpkh_address,
    }

    # Generate Toncoin Wallet
    mnemonics, pub_key, priv_key, wallet = Wallets.create(WalletVersionEnum.v4r2, workchain=0)
    ton_address = wallet.address.to_string(True, True, False)
    wallets["ton"] = {"address": ton_address, "private_key": priv_key.hex(), "blockchain": "TON"}

    return wallets

def save_wallet(wallet_type, address, private_key, mnemonics, balance, derivation_path=None):
    print(f"\n{Fore.GREEN}{wallet_type} Wallet{Style.RESET_ALL}")
    print(f"Address: {address}")
    print(f"Private Key: {private_key if private_key != 'N/A' else 'N/A'}")
    print(f"Balance: {balance} {wallet_type}")
    if derivation_path:
        print(f"Derivation Path: {derivation_path}")
    print("-" * 40)
    print(f"Mnemonic: {mnemonics}")
    print("-" * 40)

def print_title():
    title = pyfiglet.figlet_format("TonCoin Generator")
    print(Fore.CYAN + title)
    print(Fore.GREEN + "Made by Cr0mb\n")

def main():
    while True:
        mnemonic = generate_mnemonic()
        print(f"\n{Fore.BLUE}Mnemonic Phrase:{Style.RESET_ALL} {mnemonic}")

        wallets = generate_wallets(mnemonic)

        eth_balance = get_balance(wallets["eth"]["address"], "ETH")
        save_wallet("Ethereum", wallets["eth"]["address"], wallets["eth"]["private_key"], mnemonic, eth_balance, derivation_path="m/44'/60'/0'/0/0")

        with ThreadPoolExecutor() as executor:
            futures = {key: executor.submit(get_balance, address, "BTC") for key, address in wallets["btc"].items()}
            for key, future in futures.items():
                balance = future.result()
                save_wallet("Bitcoin", wallets["btc"][key], "N/A", mnemonic, balance, derivation_path="m/44'/0'/0'/0/0")

        ton_balance = get_balance(wallets["ton"]["address"], "TON")
        save_wallet("Toncoin", wallets["ton"]["address"], wallets["ton"]["private_key"], mnemonic, ton_balance, derivation_path="N/A")

        # Wait time can be added here if needed
        # print(f"{Fore.CYAN}Waiting for the next wallet generation...{Style.RESET_ALL}")
        # time.sleep(1)  # Adjust this delay as necessary to control generation speed

if __name__ == "__main__":
    main()
