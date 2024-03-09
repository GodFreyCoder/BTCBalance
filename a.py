import ecdsa
import hashlib
import base58
import requests
import random
from colorama import Fore, Style

def get_balance(bitcoin_address):
    api_url = f'https://blockchain.info/balance?active={bitcoin_address}'
    response = requests.get(api_url)

    if response.status_code == 200:
        data = response.json()
        return data.get('final_balance', 0) / 10**8  # Convert satoshis to BTC
    else:
        print(f"Error fetching balance for {bitcoin_address}: {response.status_code}")
        return 0

def generate_bitcoin_address(private_key_bytes):
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    compressed_public_key = vk.to_string("compressed")

    sha256_hash = hashlib.sha256(compressed_public_key).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    extended_ripemd160_hash = b'\x00' + ripemd160_hash
    checksum = hashlib.sha256(hashlib.sha256(extended_ripemd160_hash).digest()).digest()[:4]
    extended_hash_with_checksum = extended_ripemd160_hash + checksum

    bitcoin_address = base58.b58encode(extended_hash_with_checksum).decode('utf-8')
    return bitcoin_address

def generate_random_address(start, end):
    checked_count = 0
    while True:
        hex_private_key = ''.join(random.choice('0123456789abcdef') for _ in range(64))
        if int(start, 16) <= int(hex_private_key, 16) <= int(end, 16):
            private_key_bytes = bytes.fromhex(hex_private_key)
            generated_address = generate_bitcoin_address(private_key_bytes)
            balance = get_balance(generated_address)
            checked_count += 1
            balance_color = Fore.YELLOW if balance == 0 else Fore.GREEN
            address_color = Fore.RED if balance == 0 else Fore.GREEN
            print(f"{checked_count} | {address_color}{generated_address}{Style.RESET_ALL} | {balance_color}{balance} BTC {Style.RESET_ALL}")
            print(f"Hex: {Fore.BLUE}{hex_private_key}{Style.RESET_ALL}")
            if balance > 0:
                return hex_private_key, generated_address, balance

# Set the range in hexadecimal
start_hex = '1'
end_hex = 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140'

# Keep checking addresses until a non-zero balance is found
hex_private_key, generated_address, balance = generate_random_address(start_hex, end_hex)
print(f"Hex: {Fore.BLUE}{hex_private_key}{Style.RESET_ALL}")
print(f"Address: {Fore.RED}{generated_address}{Style.RESET_ALL}, Balance: {Fore.GREEN if balance > 0 else Fore.YELLOW}{balance}{Style.RESET_ALL} BTC")
