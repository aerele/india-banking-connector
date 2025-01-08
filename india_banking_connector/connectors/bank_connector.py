import hashlib
import json
from base64 import b64decode, b64encode, urlsafe_b64encode

import frappe
import rsa
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from frappe.model.document import Document
from jose import jwe, jws


class BankConnector(Document):
	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.validate_user_permission()
		self.bank = kwargs.get("bank")
		self.BLOCK_SIZE = kwargs.get("block_size")
		self.IV = kwargs.get("iv")
		self.AES_KEY = kwargs.get("aes_key")

	def validate_user_permission(self):
		if not frappe.has_permission("Bank Request Log", "write"):
			frappe.throw("Not permitted", frappe.PermissionError)

	def encrypt_payload(self, payload, bank):
		if bank == "HDFC Bank":
			jws_signed = self.generate_jws_with_rs256(
				payload,
				self.get_file_content(self.private_key),
				kid=self.generate_kid(self.sign_key),
			)

			encrypted_payload = jwe.encrypt(
				plaintext=jws_signed,
				key=self.get_file_content(self.public_key),
				encryption="A256GCM",
				algorithm="RSA-OAEP-256",
				cty="JWE",
				kid=self.generate_kid(self.public_key),
			)

			return encrypted_payload

	def decrypt_response(self, response, bank):
		if bank == "HDFC Bank":
			jwe_decrypted = jwe.decrypt(
				response.text.encode("utf-8"), self.get_file_content(self.private_key)
			)
			jws_verified = jws.verify(
				jwe_decrypted,
				self.get_file_content(self.public_key),
				algorithms=["RS256"],
			)
			return jws_verified.decode("utf-8")

	def generate_kid(self, file_name):
		public_key_pem_str = self.get_file_content(file_name)

		public_key_pem_bytes = public_key_pem_str.encode("utf-8")

		public_key = serialization.load_pem_public_key(
			public_key_pem_bytes, backend=default_backend()
		)

		public_key_der = public_key.public_bytes(
			encoding=serialization.Encoding.DER,
			format=serialization.PublicFormat.SubjectPublicKeyInfo,
		)

		sha256_hash = hashlib.sha256(public_key_der).digest()

		kid = urlsafe_b64encode(sha256_hash).decode("utf-8").rstrip("=")

		return kid

	def get_file_content(self, file_url):
		with open(self.get_file_relative_path(file_url), "r") as file:
			return file.read()

	def get_file_relative_path(self, file_url):
		return frappe.get_doc("File", {"file_url": file_url}).get_full_path()

	"""""" """""" """""" """""" """""" """""" """""" """'' HDFC """ """""" """""" """""" """""" """""" """""" """""" """""" """"""

	def aes_encrypt(self, data, key):
		if isinstance(key, str):
			key = key.encode("utf-8")
		if isinstance(data, str):
			data = data.encode("utf-8")

		cipher = AES.new(key, AES.MODE_CBC, self.IV)
		encrypted = cipher.encrypt(pad(data, AES.block_size))
		return b64encode(encrypted).decode("utf-8")

	def aes_decrypt(self, data, key):
		if isinstance(key, str):
			key = key.encode("utf-8")

		encrypted_bytes = b64decode(data)

		IV, encrypted_data = encrypted_bytes[:16], encrypted_bytes[16:]

		cipher = AES.new(key, AES.MODE_CBC, IV)

		decrypted_padded = cipher.decrypt(encrypted_data)

		return unpad(decrypted_padded, AES.block_size).decode("utf-8")

	"""""" """""" """""" """""" """""" """""" """""" """'' Kotak """ """""" """""" """""" """""" """""" """""" """""" """""" """"""

	# Generate JWS with RS256
	def generate_jws_with_rs256(self, content: str | dict, private_key, kid: str):
		headers = {"typ": "JWS", "kid": kid}

		# Convert content to bytes
		if isinstance(content, dict):
			content_bytes = json.dumps(content).encode("utf-8")
		else:
			content_bytes = content.encode("utf-8")

		return jws.sign(content_bytes, private_key, algorithm="RS256", headers=headers)

	def rsa_encrypt_key(self, key, key_path):
		with open(key_path, "rb") as file:
			public_key = rsa.PublicKey.load_pkcs1(file.read())
			encrypted_key = rsa.encrypt(key, public_key)
			return b64encode(encrypted_key).decode("utf-8")

	def rsa_decrypt_key(self, key, key_path):
		with open(key_path, "rb") as file:
			private_key = rsa.PrivateKey.load_pkcs1(file.read())
			return rsa.decrypt(b64decode(key), private_key).decode("utf-8")

	def rsa_encrypt_data(self, data, encrypted_key):
		if isinstance(data, dict):
			data = json.dumps(data)

		byte_data = data.encode("utf-8")

		padded = pad(byte_data, self.BLOCK_SIZE)

		cipher = AES.new(encrypted_key, AES.MODE_CBC, self.IV)

		encrypted = cipher.encrypt(padded)

		return b64encode(encrypted).decode("utf-8")

	def rsa_decrypt_data(self, data, encrypted_key):
		message = b64decode(data)

		cipher = AES.new(encrypted_key, AES.MODE_CBC, self.IV)
		decrypted = cipher.decrypt(message)

		unpaded = unpad(decrypted, self.BLOCK_SIZE)

		return json.loads(unpaded[self.BLOCK_SIZE :])
