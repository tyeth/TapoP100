import time
import json
import os
import binascii
import adafruit_requests as requests
import adafruit_hashlib as hashlib
import adafruit_rsa
import aesio
from adafruit_connection_manager import (
    ConnectionManager,
    get_radio_socketpool,
    get_radio_ssl_context,
)

# Remove direct Wi-Fi and network setup imports
# Wi-Fi and networking imports are now handled internally


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

def raise_for_status(resp):
    if resp.status_code < 200 or resp.status_code >= 300:
        print(f"Response Error: {resp.text}")
        raise Exception(f"Response Error code: {resp.status_code}")


class AuthProtocol:
    def __init__(self, address: str, username: str, password: str, radio=None):
        self._radio = radio
        if not self._radio:
            try:
                import wifi
                self.radio=wifi.radio
            except:
                pass
        if not self._radio:
            raise Exception("radio argument error: Pass in a wifi.radio object or ESP_SPIcontrol or WIZNET5K")
        self.address = address
        self.username = username
        self.password = password
        self.key = None
        self.iv = None
        self.seq = None
        self.sig = None
        # Initialize connection manager
        self._initialize_connection()

    def _initialize_connection(self):
        # Get the radio object and socket pool
        socket_pool = get_radio_socketpool(self._radio)
        ssl_context = get_radio_ssl_context(self._radio)
        # Create a connection manager and requests session
        self.connection_manager = ConnectionManager(socket_pool)
        self.session = requests.Session(socket_pool, ssl_context)

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
        print(f"Request URL: {url} Data: {data} Headers: {headers}")
        resp = self.session.post(url, data=data, headers=headers, timeout=2)
        print(f"Response status: {resp.status_code}")
        print(f"Response: {json.dumps(resp.headers)}")
        raise_for_status(resp)
        data = resp.content
        # Close the socket after use
        resp.close()
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
        print(f"Encrypted: {encrypted}")
        _request_result = self._request_raw("request", encrypted, params={"seq": self.seq})
        print(f"Encrypted response: {_request_result}")
        # Unwrap and decrypt result
        decrypted_data = self._decrypt(_request_result)
        print(f"Decrypted response: {decrypted_data}")
        data = json.loads(decrypted_data.decode("UTF-8"))
        print(f"Decrypted JSON: {data}")
        # Check error code and get result
        if data["error_code"] != 0:
            print(f"Error: {data}")
            self.key = None
            raise Exception(f"Error code: {data['error_code']}")
        _request_result = data.get("result")
        print(f"Response: {_request_result}")
        return _request_result

    def _encrypt(self, data: bytes):
        print(f"Encrypting data: {data}")
        self.seq += 1
        seq = self.seq.to_bytes(4, "big", signed=False)
        print(f"Sequence number (seq): {self.seq}, bytes: {seq}")
        # Add PKCS#7 padding
        pad_l = 16 - (len(data) % 16)
        data += bytes([pad_l] * pad_l)
        print(f"Padded data: {data}")
        # Encrypt data with key
        iv_seq = self.iv + seq
        print(f"IV + seq: {iv_seq}")
        cipher = aesio.AES(self.key, aesio.MODE_CBC, iv_seq)
        ciphertext = bytearray(len(data))
        cipher.encrypt_into(data, ciphertext)
        print(f"Ciphertext: {ciphertext}")
        # Signature
        sig = sha256(self.sig + seq + ciphertext)
        print(f"Signature: {sig}")
        encrypted_data = sig + ciphertext
        print(f"Encrypted data (sig + ciphertext): {encrypted_data}")
        return encrypted_data

    def _decrypt(self, data: bytes):
        print(f"Decrypting data: {data}")
        # Extract signature and ciphertext
        sig_received = data[:32]
        ciphertext = data[32:]
        print(f"Received signature: {sig_received}")
        print(f"Ciphertext: {ciphertext}")
        seq = self.seq.to_bytes(4, "big", signed=False)
        print(f"Sequence number (seq): {self.seq}, bytes: {seq}")
        # Verify signature
        sig_calculated = sha256(self.sig + seq + ciphertext)
        print(f"Calculated signature: {sig_calculated}")
        if sig_received != sig_calculated:
            print("Signature mismatch!")
            raise Exception("Invalid signature")
        # Decrypt data with key
        iv_seq = self.iv + seq
        print(f"IV + seq: {iv_seq}")
        cipher = aesio.AES(self.key, aesio.MODE_CBC, iv_seq)
        decrypted = bytearray(len(ciphertext))
        cipher.decrypt_into(ciphertext, decrypted)
        print(f"Decrypted data with padding: {decrypted}")
        # Remove PKCS#7 padding
        pad_l = decrypted[-1]
        print(f"Padding length: {pad_l}")
        if pad_l < 1 or pad_l > 16:
            print("Invalid padding length!")
            raise Exception("Invalid padding")
        data = decrypted[:-pad_l]
        print(f"Decrypted data without padding: {data}")
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
    def __init__(self, address: str, username: str, password: str, radio=None):
        self._radio = radio
        if not self._radio:
            try:
                import wifi
                self._radio = wifi.radio
            except:
                pass
        if not self._radio:
            raise Exception("radio argument error: Pass in a wifi.radio object or ESP_SPIcontrol or WIZNET5K")
        self.address = address
        self.username = username
        self.password = password
        # Initialize connection manager
        self._initialize_connection()
        # Generate a random UUID-like string
        self.terminal_uuid = ''.join('%02x' % b for b in os.urandom(16))
        print(f"Terminal UUID: {self.terminal_uuid}")
        # Generate RSA keypair using adafruit_rsa
        self._create_keypair()
        self.key = None
        self.iv = None
        self.token = None

    def _initialize_connection(self):
        # Get the radio object and socket pool
        socket_pool = get_radio_socketpool(self._radio)
        ssl_context = get_radio_ssl_context(self._radio)
        # Create a connection manager and requests session
        self.connection_manager = ConnectionManager(socket_pool)
        self.session = requests.Session(socket_pool, ssl_context)

    def _create_keypair(self):
        # Generate a new RSA keypair
        print("Generating RSA keypair...")
        (self.pub_key, self.priv_key) = adafruit_rsa.newkeys(1024)
        print("RSA keypair generated.")

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
        print(f"Request URL: {url}")
        print(f"Request Payload: {json.dumps(payload)}")

        # Execute call
        resp = self.session.post(url, json=payload, timeout=10)
        print(f"Response status: {resp.status_code}")
        print(f"Response headers: {json.dumps(resp.headers)}")
        print(f"Response text: {resp.text}")
        print(f"Response content: {resp.content}")
        # CircuitPython doesn't have resp.raise_for_status(), so use custom function
        raise_for_status(resp)
        data = resp.json()
        # Close the socket after use
        resp.close()

        # Check error code and get result
        if data["error_code"] != 0:
            print(f"Error in response: {data}")
            self.key = None
            raise Exception(f"Error code: {data['error_code']}")
        _request_raw_result = data.get("result")

        print(f"Response raw: {_request_raw_result}")
        return _request_raw_result

    def _request(self, method: str, params: dict = None):
        if not self.key:
            print("Key not initialized, calling Initialize()")
            self.Initialize()

        # Construct payload
        payload = {
            "method": method,
            "requestTimeMils": int(round(time.time() * 1000)),
            "terminalUUID": self.terminal_uuid,
        }
        if params:
            payload["params"] = params
        print(f"Request Payload (before encryption): {json.dumps(payload)}")

        # Encrypt payload and execute call
        encrypted = self._encrypt(json.dumps(payload))
        print(f"Encrypted Payload: {encrypted}")

        _request_result = self._request_raw("securePassthrough", {"request": encrypted})

        # Unwrap and decrypt result
        decrypted = self._decrypt(_request_result["response"])
        print(f"Decrypted Response: {decrypted}")
        data = json.loads(decrypted)
        print(f"Decrypted JSON Response: {data}")
        if data["error_code"] != 0:
            print(f"Error in decrypted response: {data}")
            self.key = None
            raise Exception(f"Error code: {data['error_code']}")
        _request_result = data.get("result")

        print(f"Final Result: {_request_result}")
        return _request_result

    def _encrypt(self, data: str):
        print(f"Encrypting data: {data}")
        data = data.encode("UTF-8")
        # Add PKCS#7 padding
        pad_l = 16 - (len(data) % 16)
        padding = bytes([pad_l] * pad_l)
        data += padding
        print(f"Padded data: {binascii.hexlify(data)} (Padding length: {pad_l})")

        # Encrypt data with key
        cipher = aesio.AES(self.key, aesio.MODE_CBC, self.iv)
        ciphertext = bytearray(len(data))
        cipher.encrypt_into(data, ciphertext)
        print(f"Ciphertext: {binascii.hexlify(ciphertext)}")

        # Base64 encode
        data_b64 = binascii.b2a_base64(ciphertext).strip()
        encrypted_data = data_b64.decode("UTF-8")
        print(f"Encrypted data (base64): {encrypted_data}")
        return encrypted_data

    def _decrypt(self, data: str):
        print(f"Decrypting data: {data}")
        # Base64 decode data
        ciphertext = binascii.a2b_base64(data.encode("UTF-8"))
        print(f"Ciphertext (base64 decoded): {binascii.hexlify(ciphertext)}")

        # Decrypt data with key
        cipher = aesio.AES(self.key, aesio.MODE_CBC, self.iv)
        decrypted = bytearray(len(ciphertext))
        cipher.decrypt_into(ciphertext, decrypted)
        print(f"Decrypted data with padding: {binascii.hexlify(decrypted)}")

        # Remove PKCS#7 padding
        pad_l = decrypted[-1]
        if pad_l < 1 or pad_l > 16:
            print("Invalid padding length!")
            raise Exception("Invalid padding")
        data = decrypted[:-pad_l]
        print(f"Decrypted data without padding: {data}")
        return data.decode("UTF-8")

    def Initialize(self):
        print("Initializing OldProtocol...")
        # Unset key and token
        self.key = None
        self.token = None

        # Send public key and receive encrypted symmetric key
        print("Preparing public key...")
        public_key_pem = adafruit_rsa.pem.save_pem(
            self.pub_key.save_pkcs1(),
            "PUBLIC KEY",
        ).decode("UTF-8")

        # Remove headers and footers for proper formatting
        public_key_pem = public_key_pem.replace("-----BEGIN PUBLIC KEY-----\n", "")
        public_key_pem = public_key_pem.replace("-----END PUBLIC KEY-----\n", "")
        public_key_pem = public_key_pem.replace("\n", "")
        print(f"Public Key PEM: {public_key_pem}")

        result = self._request_raw("handshake", {"key": public_key_pem})
        encrypted_key_b64 = result["key"]
        print(f"Received encrypted key (base64): {encrypted_key_b64}")

        # Decrypt symmetric key
        encrypted_key = binascii.a2b_base64(encrypted_key_b64.encode("UTF-8"))
        print(f"Encrypted key (base64 decoded): {binascii.hexlify(encrypted_key)}")
        decrypted_key = adafruit_rsa.pkcs1.decrypt(encrypted_key, self.priv_key)
        print(f"Decrypted symmetric key: {binascii.hexlify(decrypted_key)}")
        self.key = decrypted_key[:16]
        self.iv = decrypted_key[16:]
        print(f"Session Key (AES key): {binascii.hexlify(self.key)}")
        print(f"Initialization Vector (IV): {binascii.hexlify(self.iv)}")

        # Base64 encode password and hashed username
        hashed_username = hashlib.sha1(self.username.encode("UTF-8")).hexdigest()
        print(f"SHA1 hashed username: {hashed_username}")
        hashed_username_bytes = hashed_username.encode("UTF-8")
        username_b64 = binascii.b2a_base64(hashed_username_bytes).strip()
        password_b64 = binascii.b2a_base64(self.password.encode("UTF-8")).strip()
        print(f"Username (base64): {username_b64}")
        print(f"Password (base64): {password_b64}")

        # Send login info and receive session token
        result = self._request(
            "login_device",
            {
                "username": username_b64.decode("UTF-8"),
                "password": password_b64.decode("UTF-8"),
            },
        )
        self.token = result["token"]
        print(f"Received session token: {self.token}")
        print("Initialization complete.")

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
