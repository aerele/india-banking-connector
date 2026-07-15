import hashlib
import json
from base64 import b64decode, b64encode, urlsafe_b64encode

import frappe
import rsa
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from frappe.model.document import Document
from frappe.query_builder import DocType
from jose import jwe, jws


class BankConnector(Document):
	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.validate_user_permission()

	def is_active(self):
		if not self.active:
			frappe.throw("Connector inactive. Please contact admin.")

	@property
	def urls(self):
		end_point_url = DocType("Endpoint URLs")
		bank_api_endpoint = DocType("Bank API Endpoint")
		urls = (
			frappe.qb.from_(end_point_url)
			.join(bank_api_endpoint)
			.on(end_point_url.parent == bank_api_endpoint.name)
			.select(end_point_url.action, end_point_url.url)
			.where(bank_api_endpoint.bank == self.bank)
			.where(
				bank_api_endpoint.environment
				== ("Testing" if self.testing else "Production")
			)
			.where(
				bank_api_endpoint.bulk_transaction
				== (1 if self.bulk_transaction else 0)
			)
		).run()

		return frappe._dict(dict(urls))

	def validate_user_permission(self):
		if not frappe.has_permission("Bank Request Log", "write"):
			frappe.throw("Not permitted", frappe.PermissionError)

	def validate_duplicate_payments(self, unique_id=None, method="make_payment"):
		"""
		Validate duplicate payments by checking if a payment has already been made against the given unique ID.
		If a payment exists, fetch the already processed details and return them.
		Args:
		        unique_id (str, optional): The unique identifier for the payment. Defaults to None.
		        method (str, optional): The method to be used for formatting the response. Defaults to "make_payment".
		Returns:
		        dict: A dictionary containing the formatted response of the existing payment if found, otherwise an empty dictionary.
		"""
		if not unique_id:
			return

		res_dict = frappe._dict({})
		existing_payment_response = frappe.get_value(
			"Bank Request Log",
			{
				"unique_id": unique_id,
				"action": "Initiate Payment",
				"status_code": "200",
			},
			"decrypted_response",
		)

		if existing_payment_response and hasattr(self, "get_formated_response"):
			self.get_formated_response(
				existing_payment_response, res_dict, method=method
			)
		elif existing_payment_response:
			frappe.throw(
				frappe._(
					f"Payment with ID {unique_id} has already been processed. Aborting transaction."
				)
			)

		return res_dict

	# HDFC Encryption and Decryption
	# Generate JWS with RS256
	def generate_jws_with_rs256(self, content: str | dict, private_key, kid: str):
		headers = {"typ": "JWS", "kid": kid}

		# Convert content to bytes
		if isinstance(content, dict):
			content_bytes = json.dumps(content).encode("utf-8")
		else:
			content_bytes = content.encode("utf-8")

		return jws.sign(content_bytes, private_key, algorithm="RS256", headers=headers)

	def encrypt_payload(self, payload):
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

	def decrypt_response(self, response):
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
		import os
		# Map the URL directly to the physical file path, bypassing the File database record
		return os.path.join(frappe.utils.get_site_path(), file_url.lstrip('/'))

	# Kotak Encryption and Decryption

	def aes_encrypt(self, data, key):
		if isinstance(key, str):
			key = key.encode("utf-8")
		if isinstance(data, str):
			data = data.encode("utf-8")

		data = self.IV + data

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

	# ICICI Encryption and Decryption

	def rsa_encrypt_key(self, key, key_path):
		if isinstance(key, str):
			key = key.encode("utf-8")

		with open(key_path, "rb") as file:
			public_key = rsa.PublicKey.load_pkcs1(file.read())
			encrypted_key = rsa.encrypt(key, public_key)
			return b64encode(encrypted_key).decode("utf-8")

	def rsa_decrypt_key(self, key, key_path):
		with open(key_path, "rb") as file:
			private_key = rsa.PrivateKey.load_pkcs1(file.read())
			return rsa.decrypt(b64decode(key), private_key).decode("utf-8")

	def aes_encrypt_data(self, data, key):
		if isinstance(data, dict):
			data = json.dumps(data)

		if isinstance(key, str):
			key = key.encode("utf-8")

		padded = pad(data.encode("utf-8"), AES.block_size)

		cipher = AES.new(key, AES.MODE_CBC, self.IV)

		encrypted = cipher.encrypt(padded)

		return b64encode(encrypted).decode("utf-8")

	def aes_decrypt_data(self, data, key, json_loads=True):
		if isinstance(key, str):
			key = key.encode("utf-8")

		cipher = AES.new(key, AES.MODE_CBC, self.IV)

		decrypted = cipher.decrypt(b64decode(data))

		if not json_loads:
			return unpad(decrypted, AES.block_size).decode("utf-8")

		return json.loads(unpad(decrypted, AES.block_size))

	def rsa_encrypt_data(self, data, key_path):
		if isinstance(data, dict):
			data = json.dumps(data)

		public_key = open(key_path, "r")
		rsa_key = RSA.importKey(public_key.read())

		cipher = Cipher_PKCS1_v1_5.new(rsa_key)
		cipher_text = cipher.encrypt(data.encode())

		return b64encode(cipher_text).decode()

	def rsa_with_aes_decrypt_data(self, data, key):
		decoded_data = b64decode(data)
		iv = decoded_data[:16]
		encrypted_content = decoded_data[16:]

		cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
		decrypted_data = cipher.decrypt(encrypted_content)

		padding_length = decrypted_data[-1]
		decrypted_data = decrypted_data[:-padding_length]

		return decrypted_data.decode("utf-8")

	def rsa_decrypt_data(self, data, key_path):
		rsa_key = RSA.importKey(open(key_path, "rb").read())
		decoded_data = b64decode(data)

		cipher = Cipher_PKCS1_v1_5.new(rsa_key)

		decrypted_res = cipher.decrypt(decoded_data, b"x")

		return json.loads(decrypted_res.decode("utf-8"))
