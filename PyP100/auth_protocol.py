import time
import json
import os
import binascii
import adafruit_requests as requests
import adafruit_hashlib as hashlib
import adafruit_rsa
import aesio

# Wi-Fi and networking imports
import wifi
import socketpool
import ssl
from secrets import secrets  # For Wi-Fi credentials

# Connect to Wi-Fi
print("Connecting to Wi-Fi...")
wifi.radio.connect(secrets["ssid"], secrets["password"])
print("Connected to Wi-Fi!")

# Create a socket pool and SSL context
pool = socketpool.SocketPool(wifi.radio)
ssl_context = ssl.create_default_context()

# Initialize the requests session
session = requests.Session(pool, ssl_context)


def sha1(data: bytes) -> bytes:
    hash_object = hashlib.sha1()
    hash_object.update(data)
    return hash_object.digest()


def sha256(data: bytes) -> bytes:
    hash_object = hashlib.sha256()
    hash_object.update(data)
    return hash_object.digest()


def get_random_bytes(length: int) -> bytes:
    return os.urandom(length)


class AuthProtocol:
    def __init__(self, address: str, username: str, password: str):
        self.session = session  # Use the initialized session
        self.address = address
        self.username = username
        self.password = password
        self.key = None
        self.iv = None
        self.seq = None
        self.sig = None

    def calc_auth_hash(self, username: str, password: str) -> bytes:
        return sha256(sha1(username.encode()) + sha1(password.encode()))

    def _request_raw(self, path: str, data: bytes, params: dict = None):
        url = f"http://{self.address}/app/{path}"
        headers = {
            "Content-Type": "application/octet-stream",
        }
        if params:
            # Manually append parameters to the URL
            url += '?' + '&'.join([f"{k}={v}" for k, v in params.items()])
        resp = self.session.post(url, data=data, headers=headers, timeout=2)
        resp.raise_for_status()
        data = resp.content
        return data

    def _request(self, method: str, params: dict = None):
        if not self.key:
            self.Initialize()
        payload = {"method": method}
        if params:
            payload["params"] = params
        print(f"Request: {payload}")
        # Encrypt payload and execute call
        encrypted = self._encrypt(json.dumps(payload).encode("UTF-8"))
        result = self._request_raw("request", encrypted, params={"seq": self.seq})
        # Unwrap and decrypt result
        decrypted_data = self._decrypt(result)
        data = json.loads(decrypted_data.decode("UTF-8"))
        # Check error code and get result
        if data["error_code"] != 0:
            print(f"Error: {data}")
            self.key = None
            raise Exception(f"Error code: {data['error_code']}")
        result = data.get("result")
        print(f"Response: {result}")
        return result

    def _encrypt(self, data: bytes):
        self.seq += 1
        seq = self.seq.to_bytes(4, "big", signed=False)
        # Add PKCS#7 padding
        pad_l = 16 - (len(data) % 16)
        data += bytes([pad_l] * pad_l)
        # Encrypt data with key
        iv_seq = self.iv + seq
        cipher = aesio.AES(self.key, aesio.MODE_CBC, iv_seq)
        ciphertext = bytearray(len(data))
        cipher.encrypt_into(data, ciphertext)
        # Signature
        sig = sha256(self.sig + seq + ciphertext)
        return sig + ciphertext

    def _decrypt(self, data: bytes):
        # Extract signature and ciphertext
        sig_received = data[:32]
        ciphertext = data[32:]
        seq = self.seq.to_bytes(4, "big", signed=False)
        # Verify signature
        sig_calculated = sha256(self.sig + seq + ciphertext)
        if sig_received != sig_calculated:
            raise Exception("Invalid signature")
        # Decrypt data with key
        iv_seq = self.iv + seq
        cipher = aesio.AES(self.key, aesio.MODE_CBC, iv_seq)
        decrypted = bytearray(len(ciphertext))
        cipher.decrypt_into(ciphertext, decrypted)
        # Remove PKCS#7 padding
        pad_l = decrypted[-1]
        if pad_l < 1 or pad_l > 16:
            raise Exception("Invalid padding")
        data = decrypted[:-pad_l]
        return data

    def Initialize(self):
        local_seed = get_random_bytes(16)
        response = self._request_raw("handshake1", local_seed)
        remote_seed, server_hash = response[:16], response[16:]
        auth_hash = None
        credentials = [
            (self.username, self.password),
            ("", ""),
            ("kasa@tp-link.net", "kasaSetup"),
        ]
        for creds in credentials:
            ah = self.calc_auth_hash(*creds)
            local_seed_auth_hash = sha256(local_seed + remote_seed + ah)
            if local_seed_auth_hash == server_hash:
                auth_hash = ah
                print(f"Authenticated with {creds[0]}")
                break
        if not auth_hash:
            raise Exception("Failed to authenticate")
        self._request_raw("handshake2", sha256(remote_seed + local_seed + auth_hash))
        lsk_input = b"lsk" + local_seed + remote_seed + auth_hash
        self.key = sha256(lsk_input)[:16]
        ivseq = sha256(b"iv" + local_seed + remote_seed + auth_hash)
        self.iv = ivseq[:12]
        self.seq = int.from_bytes(ivseq[-4:], "big", signed=False)
        self.sig = sha256(b"ldk" + local_seed + remote_seed + auth_hash)[:28]
        print("Initialized")


class OldProtocol:
    def __init__(self, address: str, username: str, password: str):
        self.session = session  # Use the initialized session
        # Generate a random UUID-like string
        self.terminal_uuid = ''.join('%02x' % b for b in os.urandom(16))
        self.address = address
        self.username = username
        self.password = password
        # Generate RSA keypair using adafruit_rsa
        self._create_keypair()
        self.key = None
        self.iv = None
        self.token = None

    def _create_keypair(self):
        # Generate a new RSA keypair
        (self.pub_key, self.priv_key) = adafruit_rsa.newkeys(1024)
        # No need to save to file in CircuitPython

    def _request_raw(self, method: str, params: dict = None):
        # Construct URL, add token if we have one
        url = f"http://{self.address}/app"
        if self.token:
            url += f"?token={self.token}"

        # Construct payload
        payload = {
            "method": method,
            "requestTimeMils": int(round(time.time() * 1000)),
            "terminalUUID": self.terminal_uuid,
        }
        if params:
            payload["params"] = params
        print(f"Request raw: {payload}")

        # Execute call
        resp = self.session.post(url, json=payload, timeout=2)
        resp.raise_for_status()
        data = resp.json()

        # Check error code and get result
        if data["error_code"] != 0:
            print(f"Error: {data}")
            self.key = None
            raise Exception(f"Error code: {data['error_code']}")
        result = data.get("result")

        print(f"Response raw: {result}")
        return result

    def _request(self, method: str, params: dict = None):
        if not self.key:
            self.Initialize()

        # Construct payload
        payload = {
            "method": method,
            "requestTimeMils": int(round(time.time() * 1000)),
            "terminalUUID": self.terminal_uuid,
        }
        if params:
            payload["params"] = params
        print(f"Request: {payload}")

        # Encrypt payload and execute call
        encrypted = self._encrypt(json.dumps(payload))

        result = self._request_raw("securePassthrough", {"request": encrypted})

        # Unwrap and decrypt result
        decrypted = self._decrypt(result["response"])
        data = json.loads(decrypted)
        if data["error_code"] != 0:
            print(f"Error: {data}")
            self.key = None
            raise Exception(f"Error code: {data['error_code']}")
        result = data.get("result")

        print(f"Response: {result}")
        return result

    def _encrypt(self, data: str):
        data = data.encode("UTF-8")

        # Add PKCS#7 padding
        pad_l = 16 - (len(data) % 16)
        data += bytes([pad_l] * pad_l)

        # Encrypt data with key
        cipher = aesio.AES(self.key, aesio.MODE_CBC, self.iv)
        ciphertext = bytearray(len(data))
        cipher.encrypt_into(data, ciphertext)

        # Base64 encode
        data_b64 = binascii.b2a_base64(ciphertext).strip()
        return data_b64.decode("UTF-8")

    def _decrypt(self, data: str):
        # Base64 decode data
        ciphertext = binascii.a2b_base64(data.encode("UTF-8"))

        # Decrypt data with key
        cipher = aesio.AES(self.key, aesio.MODE_CBC, self.iv)
        decrypted = bytearray(len(ciphertext))
        cipher.decrypt_into(ciphertext, decrypted)

        # Remove PKCS#7 padding
        pad_l = decrypted[-1]
        data = decrypted[:-pad_l]
        return data.decode("UTF-8")

    def Initialize(self):
        # Unset key and token
        self.key = None
        self.token = None

        # Send public key and receive encrypted symmetric key
        public_key_pem = adafruit_rsa.pem.save_pem(
            self.pub_key.save_pkcs1(),
            "PUBLIC KEY",
        ).decode("UTF-8")

        # Remove headers and footers for proper formatting
        public_key_pem = public_key_pem.replace("-----BEGIN PUBLIC KEY-----\n", "")
        public_key_pem = public_key_pem.replace("-----END PUBLIC KEY-----\n", "")
        public_key_pem = public_key_pem.replace("\n", "")

        result = self._request_raw("handshake", {"key": public_key_pem})
        encrypted_key_b64 = result["key"]

        # Decrypt symmetric key
        encrypted_key = binascii.a2b_base64(encrypted_key_b64.encode("UTF-8"))
        decrypted_key = adafruit_rsa.pkcs1.decrypt(encrypted_key, self.priv_key)
        self.key = decrypted_key[:16]
        self.iv = decrypted_key[16:]

        # Base64 encode password and hashed username
        hashed_username = hashlib.sha1(self.username.encode("UTF-8")).hexdigest()
        hashed_username_bytes = hashed_username.encode("UTF-8")
        username_b64 = binascii.b2a_base64(hashed_username_bytes).strip()
        password_b64 = binascii.b2a_base64(self.password.encode("UTF-8")).strip()

        # Send login info and receive session token
        result = self._request(
            "login_device",
            {
                "username": username_b64.decode("UTF-8"),
                "password": password_b64.decode("UTF-8"),
            },
        )
        self.token = result["token"]


# Usage example
if __name__ == "__main__":
    # Replace with your device's address, username, and password
    address = "192.168.1.100"
    username = "admin"
    password = "your_password"

    # Choose the protocol you need
    auth = AuthProtocol(address, username, password)
    # Or use OldProtocol if needed
    # auth = OldProtocol(address, username, password)

    # Example method call
    try:
        result = auth._request("get_device_info")
        print("Device Info:", result)
    except Exception as e:
        print("An error occurred:", e)
