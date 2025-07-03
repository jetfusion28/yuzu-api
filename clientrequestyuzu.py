import requests
import json
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import oqs

# Server URL
SERVER_URL = "https://yuzu-api.citrustech.io"
KEY_STORAGE_FILE = "client_keys.json"

def load_keys():
    if os.path.exists(KEY_STORAGE_FILE):
        with open(KEY_STORAGE_FILE, "r") as f:
            data = json.load(f)
            client_id = data.get("client_id")
            api_key = data.get("api_key")
            private_key_b64 = data.get("private_key")
            private_key = base64.b64decode(private_key_b64) if private_key_b64 else None
            return client_id, api_key, private_key
    return None, None, None

def save_keys(client_id, api_key, private_key):
    with open(KEY_STORAGE_FILE, "w") as f:
        json.dump({
            "client_id": client_id,
            "api_key": api_key,
            "private_key": base64.b64encode(private_key).decode()
        }, f)
    print("✅ Client ID, API Key & Kyber Private Key saved.")

def authenticate(client_id):
    with oqs.KeyEncapsulation('Kyber512') as kem:
        public_key = kem.generate_keypair()
        private_key = kem.export_secret_key()

        response = requests.post(
            f"{SERVER_URL}/authenticate",
            json={
                "client_id": client_id,
                "public_key": base64.b64encode(public_key).decode()
            }
        )

        if response.status_code == 200:
            data = response.json()
            api_key = data["api_key"]
            save_keys(client_id, api_key, private_key)
            print(f"✅ Authentication Successful! API Key: {api_key}")
            return api_key, private_key
        else:
            print(f"❌ Authentication Failed: {response.json()}")
            return None, None

def decrypt_data(encrypted_data, iv, session_key):
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_data.rstrip(b'\x00')

def request_random(client_id, api_key, private_key, total_size_MB, output_file="qrng_random_new.bin", chunk_size=5*1024*1024):
    total_size = 1024 * 1024 * total_size_MB
    url = f"{SERVER_URL}/random"
    headers = {
        "api-key": api_key,
        "client-id": client_id
    }

    downloaded = 0
    chunk_index = 1

    with open(output_file, "wb") as f:
        while downloaded < total_size:
            current_chunk_size = min(chunk_size, total_size - downloaded)
            print(f"📦 Requesting chunk {chunk_index} of {current_chunk_size} bytes...")

            response = requests.get(url, headers=headers, params={"size": current_chunk_size})
            if response.status_code != 200:
                print(f"❌ Request failed at chunk {chunk_index}: {response.status_code} - {response.text}")
                break

            data = response.json()
            ciphertext = base64.b64decode(data["ciphertext"])
            encrypted_data = base64.b64decode(data["encrypted_data"])
            iv = base64.b64decode(data["iv"])

            # ✅ Correct way: initialize with the secret key
            with oqs.KeyEncapsulation('Kyber512', secret_key=private_key) as kem:
                shared_secret = kem.decap_secret(ciphertext)

            aes_key = shared_secret[:32]
            decrypted_data = decrypt_data(encrypted_data, iv, aes_key)

            session_key = decrypted_data[:32]
            random_chunk = decrypted_data[32:32 + current_chunk_size]

            f.write(random_chunk)
            downloaded += len(random_chunk)
            chunk_index += 1

            print(f"✅ Downloaded {len(random_chunk)} bytes (Total: {downloaded} / {total_size})")

    print(f"\n🎉 Finished downloading {downloaded} bytes to {output_file}")


if __name__ == "__main__":
    client_id, api_key, private_key = load_keys()

    if not api_key or not private_key or not client_id:
        client_id = input("Enter your Client ID: ").strip()
        print("🔍 No stored keys found. Authenticating...")
        api_key, private_key = authenticate(client_id)

    if api_key and private_key and client_id:
        size = int(input("Enter the size of random data to request (in MB): "))
        request_random(client_id, api_key, private_key, size, output_file="qrng_random_new.bin")
