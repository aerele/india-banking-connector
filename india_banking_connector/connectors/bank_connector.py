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

ACTIONS = [
	"host",
	"make_payment",
	"payment_status",
	"bank_balance",
	"bank_statement",
	"register",
	"registration_status",
]


class BankConnector(Document):
	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.validate_user_permission()

	def is_active(self):
		if not self.active:
			frappe.throw("Connector inactive. Please contact admin.")

	@property
	def urls(self):
		CONNECTOR = DocType(self.doctype)
		EU = DocType("Endpoint URLs")
		urls = (
			frappe.qb.from_(CONNECTOR)
			.join(EU)
			.on(EU.parent == self.name)
			.select(EU.action, EU.url)
			.orderby(EU.idx)
		).run()

		return frappe._dict(dict(urls))

	def get_cert(self):
		return (
			self.get_file_relative_path(self.cert),
			self.get_file_relative_path(self.private_key),
		)

	def validate_user_permission(self):
		if not frappe.has_permission("Bank Request Log", "write"):
			frappe.throw("Not permitted", frappe.PermissionError)

	def get_response(self, method):
		self.is_active()
		if method and hasattr(self, method):
			return getattr(self, method)()
		else:
			frappe.throw(f"Unknown method {method} in connector {self.name}")

	def validate_duplicate_payments(self, unique_id=None, method="make_payment"):
		"""
		Checks for duplicate payments based on unique_id.

		:param unique_id: Unique identifier for the payment
		:param method: Method name for context (default: "make_payment")
		:return: Dictionary with payment status or None if no duplicate found
		"""

		if not unique_id:
			return

		bank_request_log = frappe.db.exists(
			"Bank Request Log",
			{
				"unique_id": unique_id,
				"action": "Initiate Payment",
				"status_code": "200",
			},
		)

		# If no success payment found, return None
		if not bank_request_log:
			return None

		bank_request_log = frappe.get_doc("Bank Request Log", bank_request_log)

		# Get existing success payment response
		return self.get_existing_payment_response(
			bank_request_log, unique_id, method=method
		)

	def get_existing_payment_response(
		self, bank_request_log, unique_id, method="make_payment"
	):
		from india_banking_connector.utils import ResponseObject, decrypt

		res_dict = frappe._dict({})
		response = bank_request_log.response
		decrypted_response = bank_request_log.decrypted_response

		if decrypted_response and hasattr(self, "get_formated_response"):
			existing_decrypted_response = decrypted_response
			try:
				if bank_request_log.get("encrypted"):
					existing_decrypted_response = decrypt(decrypted_response)
			except Exception:
				frappe.log_error("Response decryption Failed!")
				res_dict.update(
					{
						"status": "failed",
						"message": "Response decryption Failed!",
					}
				)
				return

			if existing_decrypted_response:
				self.get_formated_response(
					existing_decrypted_response, res_dict, method=method
				)
				if not res_dict:
					res_dict.status = "failed"
					res_dict.message = "Failed to fetch existing payment response."

		elif decrypted_response:
			frappe.throw(
				frappe._(
					f"Payment with ID {unique_id} has already been processed. Aborting transaction."
				)
			)

		elif response:
			if bank_request_log.get("encrypted"):
				response = decrypt(response)

			response = ResponseObject(response, 200)
			decrypted_response = self.get_decrypted_response(
				response,
				method="make_payment",
				log_id=bank_request_log.name,
			)

			if decrypted_response:
				res_dict.update(decrypted_response)
			else:
				res_dict.status = "failed"
				res_dict.message = "Failed to fetch existing payment response."

		return res_dict

	def get_summary_details(self, status):
		summary_details = {}

		if not self.doc:
			return summary_details

		for summary in self.doc.summary:
			summary_details.update({summary.get("name"): {"payment_status": status}})

		return summary_details

	def sign_jws(
		self,
		content_bytes: dict | str | bytes,
		sign_key: str,
		headers: dict | None = None,
		algorithm: str = "RS256",
	) -> bytes:
		if isinstance(content_bytes, dict):
			content_bytes = json.dumps(content_bytes)

		if isinstance(content_bytes, str):
			content_bytes = content_bytes.encode("utf-8")

		return jws.sign(content_bytes, sign_key, algorithm=algorithm, headers=headers)

	def jwe_encrypt(
		self,
		plaintext: str | bytes | dict,
		encryption_key: str,
		media_type: str | None = "JWE",
		encryption="A256GCM",
		algorithm="RSA-OAEP-256",
		kid=None,
	):
		if isinstance(plaintext, dict):
			plaintext = json.dumps(plaintext)
		if isinstance(plaintext, str):
			plaintext = plaintext.encode()

		return jwe.encrypt(
			plaintext=plaintext,
			key=encryption_key,
			encryption=encryption,
			algorithm=algorithm,
			cty=media_type,
			kid=kid,
		)

	def jwe_decrypt(self, text: str | bytes, decryption_key: str) -> bytes:
		if isinstance(text, str):
			text = text.encode("utf-8")

		return jwe.decrypt(text, decryption_key)

	def jws_verify(
		self, text: bytes, verify_key: str, algorithms: list[str] = ["RS256"]
	) -> str:
		jws_verified = jws.verify(
			text,
			verify_key,
			algorithms=algorithms,
		)

		return jws_verified.decode("utf-8")

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
		return frappe.get_doc("File", {"file_url": file_url}).get_full_path()

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

	def aes_encrypt_data(self, data, key, prepend_iv=False):
		if isinstance(data, dict):
			data = json.dumps(data)

		if isinstance(key, str):
			key = key.encode("utf-8")

		padded = pad(data.encode("utf-8"), AES.block_size)

		cipher = AES.new(key, AES.MODE_CBC, self.IV)

		encrypted = cipher.encrypt(padded)

		if prepend_iv:
			encrypted = self.IV + encrypted

		return b64encode(encrypted).decode("utf-8")

	def aes_decrypt_data(self, data, key, json_loads=True):
		if isinstance(key, str):
			key = key.encode("utf-8")

		cipher = AES.new(key, AES.MODE_CBC, self.IV)
		decrypted = cipher.decrypt(b64decode(data))

		if not json_loads:
			return unpad(decrypted, AES.block_size).decode("utf-8")

		error = None
		try:
			return json.loads(unpad(decrypted, AES.block_size).decode("utf-8"))
		except Exception as e:
			error = e
			try:
				# ignoring IV (if included in decrypted data)
				decrypted = decrypted[len(self.IV) :]
				return json.loads(unpad(decrypted, AES.block_size).decode("utf-8"))
			except Exception:
				frappe.log_error(
					"Connector Error", frappe.get_traceback(with_context=True)
				)
		if error:
			frappe.throw(title="Decryption Failed", msg=error)

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

	def set_decrypted_response(self, log_id, response_data):
		from frappe.utils import cstr

		from india_banking_connector.utils import encrypt

		_encrypt = frappe.db.exists(
			"Connector Map",
			{
				"connector": self.doctype,
				"encrypt_log": 1,
			},
		)

		try:
			if _encrypt:
				response_data = cstr(encrypt(response_data))
			else:
				if isinstance(response_data, str):
					response_data = json.loads(response_data)
				response_data = json.dumps(response_data, indent=4)
		except Exception:
			frappe.log_error("Response Encryption Failed!")
		if frappe.db.exists("Bank Request Log", log_id):
			frappe.db.set_value(
				"Bank Request Log",
				log_id,
				{
					"decrypted_response": response_data,
					"encrypted": 1 if _encrypt else 0,
				},
			)

	@frappe.whitelist()
	def reset_endpoints(self):
		self.api_endpoints = []
		self.extend(
			"api_endpoints",
			[{"action": action, "url": ""} for action in ACTIONS],
		)

	def on_update(self):
		if self.has_value_changed("base_url"):
			self.update_endpoints()

	def update_endpoints(self):
		from urllib.parse import urlparse

		updated_endpoints = []
		for row in self.api_endpoints:
			if row.action == "host":
				parsed = urlparse(self.base_url)
				url = parsed.netloc
			elif not row.url:
				url = ""
			else:
				parsed = urlparse(row.url)
				url = self.base_url + "/" + parsed.path.lstrip("/")
				if not self.testing and url and urlparse(url).scheme != "https":
					print(url)
					frappe.throw("URL must use HTTPS")

			updated_endpoints.append(
				{
					"action": row.action,
					"url": url,
				}
			)
		self.api_endpoints = []
		self.extend(
			"api_endpoints",
			updated_endpoints,
		)
