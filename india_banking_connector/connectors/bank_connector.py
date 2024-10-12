import frappe
from Crypto.Util.Padding import pad
from base64 import b64decode, b64encode
from random import randint
import json
import rsa
import re
import random, string
from Crypto.Cipher import AES
from frappe.model.document import Document
from jose import jws, jwe
from cryptography.hazmat.primitives import serialization
import hashlib
import base64
from cryptography.hazmat.backends import default_backend
from Crypto.Util.Padding import unpad

class BankConnector(Document):
	unpad_pkcs5 = lambda s: s[:-ord(s[len(s) - 1:])]

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.validate_user_permission()
		self.bank = kwargs.get('bank')
		self.BLOCK_SIZE = kwargs.get('block_size')
		self.IV = kwargs.get('iv')
		self.AES_KEY = kwargs.get('aes_key')

	def encrypt_payload(self, payload, bank):
		if bank == 'HDFC Bank':
			jws_signed = self.generate_jws_with_rs256(payload, self.get_file_content(self.private_key), kid= self.generate_kid(self.sign_key))

			encrypted_payload = jwe.encrypt(
				plaintext= jws_signed,
				key= self.get_file_content(self.public_key),
				encryption="A256GCM",
				algorithm="RSA-OAEP-256",
				cty="JWE",
				kid= self.generate_kid(self.public_key)
			)

			return encrypted_payload

	def generate_kid(self, file_name):
		file_path = frappe.get_doc("File", {"file_url": file_name}).get_full_path()
		with open(file_path, 'r') as f:
			public_key_pem_str = f.read()

		public_key_pem_bytes = public_key_pem_str.encode('utf-8')

		public_key = serialization.load_pem_public_key(public_key_pem_bytes, backend=default_backend())

		public_key_der = public_key.public_bytes(
			encoding=serialization.Encoding.DER,
			format=serialization.PublicFormat.SubjectPublicKeyInfo
		)

		sha256_hash = hashlib.sha256(public_key_der).digest()

		kid = base64.urlsafe_b64encode(sha256_hash).decode('utf-8').rstrip('=')

		return kid

	def get_file_content(self, file_name):
		file_path = frappe.get_doc("File", {"file_url": file_name}).get_full_path()
		with open(file_path) as file:
			return file.read()

	# Generate JWS with RS256
	def generate_jws_with_rs256(self, content: str | dict, private_key, kid: str):
		headers = {"typ": "JWS", 'kid': kid}

		# Convert content to bytes
		if isinstance(content, dict):
			content_bytes = json.dumps(content).encode('utf-8')
		else:
			content_bytes = content.encode('utf-8')

		return jws.sign(content_bytes, private_key, algorithm='RS256', headers=headers)

	def decrypt_response(self, response, bank):
		if bank == 'HDFC Bank':
			jwe_decrypted = jwe.decrypt(response.text.encode('utf-8'), self.get_file_content(self.private_key))
			jws_verified = jws.verify(jwe_decrypted, self.get_file_content(self.public_key), algorithms=['RS256'])
			return jws_verified.decode('utf-8')
	''''''''''''''''''''''''''''''''''''''''''''''' HDFC '''''''''''''''''''''''''''''''''''''''''''''''''''''''''
	def rsa_encrypt_key(self, key, key_path):
		with open(key_path, "rb") as file:
			public_key = rsa.PublicKey.load_pkcs1(file.read())
			encrypted_key = rsa.encrypt(key, public_key)
			return b64encode(encrypted_key).decode('utf-8')

	def rsa_decrypt_key(self, key, key_path):
		with open(key_path, 'rb') as file:
				private_key = rsa.PrivateKey.load_pkcs1(file.read())
				return rsa.decrypt(b64decode(key), private_key).decode('utf-8')

	def rsa_encrypt_data(self, data, encrypted_key):
		if isinstance(data, dict):
			byte_data = json.dumps(data).encode("utf-8")

		padded = pad(byte_data, self.BLOCK_SIZE)

		cipher = AES.new(encrypted_key, AES.MODE_CBC, self.IV)

		encrypted = cipher.encrypt(padded)

		return  b64encode(encrypted).decode('utf-8')

	def rsa_decrypt_data(self, data, encrypted_key):
		message = b64decode(data)

		cipher= AES.new(encrypted_key, AES.MODE_CBC, self.IV)
		decrypted = cipher.decrypt(message)

		unpaded = unpad(decrypted, self.BLOCK_SIZE)

		return json.loads(unpaded[self.BLOCK_SIZE:])

	def validate_user_permission(self):
		if not frappe.has_permission("Bank Request Log", "write"):
			frappe.throw("Not permitted", frappe.PermissionError)

	def get_file_relative_path(self, file_name):
		return frappe.get_doc("File", {"file_url": file_name}).get_full_path()