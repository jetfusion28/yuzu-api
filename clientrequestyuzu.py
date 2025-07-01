import requests
import json
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from kyber_py.kyber import Kyber512

# Server URL
SERVER_URL = "https://yuzu-api.citrustech.io"


# Client ID
CLIENT_ID = "client_001"

# Certificate for SSL verification
#CERT_FILE = "cert.pem"

# Key storage
KEY_STORAGE_FILE = "client_keys.json"


def load_keys():
    """Load API key and Kyber private key from local storage."""
    if os.path.exists(KEY_STORAGE_FILE):
        with open(KEY_STORAGE_FILE, "r") as f:
            data = json.load(f)
            api_key = data.get("api_key")
            private_key_b64 = data.get("private_key")

            if private_key_b64:
                private_key = base64.b64decode(private_key_b64)
                return api_key, private_key
    return None, None


def save_keys(api_key, private_key):
    """Save API key and Kyber private key to local storage."""
    try:
        with open(KEY_STORAGE_FILE, "w") as f:
            json.dump({"api_key": api_key, "private_key": base64.b64encode(private_key).decode()}, f)
        print(f"✅ API Key & Kyber Private Key saved.")
    except Exception as e:
        print(f"❌ Error saving keys: {e}")


def authenticate():
    """Authenticate with the server and retrieve an API key & Kyber key pair."""
    url = f"{SERVER_URL}/authenticate"
    
    # Generate a fresh Kyber512 keypair for this session
    public_key, private_key = Kyber512.keygen()

    response = requests.post(url, json={"client_id": CLIENT_ID, "public_key": base64.b64encode(public_key).decode()})

    if response.status_code == 200:
        data = response.json()
        api_key = data["api_key"]
        save_keys(api_key, private_key)  # Store API key and private key locally
        print(f"✅ Authentication Successful! API Key: {api_key}")
        return api_key, private_key
    else:
        print(f"❌ Authentication Failed: {response.json()}")
        return None, None


def decrypt_data(encrypted_data, iv, session_key):
    """Decrypt data using AES-256."""
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_data.rstrip(b'\x00')  # Remove padding


def request_random(api_key, private_key, total_size_MB, output_file="qrng_random_new.bin", chunk_size=5*1024*1024):
    total_size=1024*1024*total_size_MB
    """Fetch QRNG data in 10MB chunks until total_size is reached, saving to output_file."""
    url = f"{SERVER_URL}/random"
    headers = {
        "api-key": api_key,
        "client-id": CLIENT_ID
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

            shared_secret = Kyber512.decaps(private_key, ciphertext)
            aes_key = shared_secret[:32]
            decrypted_data = decrypt_data(encrypted_data, iv, aes_key)

            session_key = decrypted_data[:32]
            random_chunk = decrypted_data[32:32 + current_chunk_size]

            f.write(random_chunk)
            downloaded += len(random_chunk)
            chunk_index += 1

            print(f"✅ Downloaded {len(random_chunk)} bytes (Total: {downloaded} / {total_size})")
         #   if not all(data["test_results"].values()):
         #       print("⚠️ Some randomness tests failed! Consider increasing per-request size.")

    print(f"\n🎉 Finished downloading {downloaded} bytes to {output_file}")


if __name__ == "__main__":
    # Step 1: Load stored keys or authenticate
    api_key, private_key = load_keys()

    if not api_key or not private_key:
        print("🔍 No stored keys found. Authenticating...")
        api_key, private_key = authenticate()

    # Step 2: Allow user to request a specific size of random numbers
    size = int(input("Enter the size of random data to request (in MB): "))

    if api_key and private_key:
       request_random(api_key, private_key, size, output_file="qrng_random_new.bin")
      
