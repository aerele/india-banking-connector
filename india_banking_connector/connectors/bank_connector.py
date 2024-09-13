import frappe
from Crypto.Util.Padding import pad
from base64 import b64decode, b64encode
from random import randint
import json
import rsa
from Crypto.Cipher import AES
from frappe.model.document import Document


class BankConnector(Document):
	unpad_pkcs5 = lambda s: s[:-ord(s[len(s) - 1:])]

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.validate_user_permission()
		self.bank = kwargs.get('bank')
		self.BLOCK_SIZE = kwargs.get('BLOCK_SIZE')

	def get_basic_defaults(self, BLOCK_SIZE=16):
		return frappe._dict({
			"block_size" : self.BLOCK_SIZE,
			"aes_key": self.generate_aes_key(self.BLOCK_SIZE),
			"iv": self.generate_aes_key(self.BLOCK_SIZE).encode("utf-8"),
		})

	def validate_user_permission(self):
		if not frappe.has_permission("Bank Request Log", "write"):
			frappe.throw("Not permitted", frappe.PermissionError)
	
	@property
	def headers(self):
		if self.bank == "ICICI Bank" and self.bulk_transaction:
			return {
				"accept": "application/json",
				"content-type": "application/json",
				"apikey": self.get_password("api_key")
			}
	
	@property
	def urls(self):
		if self.bank == "ICICI Bank" and self.bulk_transaction:
			return frappe._dict({
				"generate_otp" : "https://apibankingone.icicibank.com/api/Corporate/CIB/v1/Create",
				"make_payment" : "https://apibankingone.icicibank.com/api/v1/cibbulkpayment/bulkPayment",
				"get_payment_status" : "https://apibankingone.icicibank.com/api/v1/ReverseMis",
				"get_balance": "https://apibankingone.icicibank.com/api/Corporate/CIB/v1/BalanceInquiry",
				"get_statement": "https://apibankingonesandbox.icicibank.com/api/Corporate/CIB/v1/AccountStatement",
				"get_statement_paginated": "https://apibankingonesandbox.icicibank.com/api/Corporate/CIB/v1/AccountStatements"
			})
	
	def get_payload(self, encrypted_key, encrypted_data, request_id= None):
		return {
			"requestId": request_id or self.generate_aes_key(7),
			"service": "",
			"oaepHashingAlgorithm": "NONE",
			"encryptedKey": encrypted_key,
			"encryptedData": encrypted_data,
			"clientInfo": "",
			"optionalParam": "",
			"iv": ""
		}

	def get_file_relative_path(self, file_name):
		file = frappe.get_doc("File", {"file_url": file_name}).get_full_path()

	def encrypt_data(self, data: str):
		if isinstance(data, str):
			data = data.encode('utf-8')

		padded = pad(self.IV + data, self.BLOCK_SIZE)
		cipher = AES.new(self.asc_key.encode("utf-8"), AES.MODE_CBC, self.IV)
		encrypted = cipher.encrypt(padded)
		return b64encode(encrypted).decode('utf-8')
	
	def encrypt_key(self, key, public_key_file_path):
		with open(public_key_file_path, 'rb') as p:
			public_key = rsa.PublicKey.load_pkcs1(p.read())
			encrypted_key = rsa.encrypt(key.encode('utf-8'), public_key)
			return b64encode(encrypted_key).decode('utf-8')

	def decrypt_key(self, key, private_key_file_path):
		with open(private_key_file_path, 'r') as p:
			private_key = rsa.PrivateKey.load_pkcs1(p.read())
			decrypted_key = rsa.decrypt(b64decode(key), private_key)
			return decrypted_key.decode('utf-8')
	
	def generate_aes_key(self, num_chars= 16):
		lower_bound = 10 ** (num_chars - 1)
		upper_bound = 10 ** num_chars - 1
		return '{:0{width}d}'.format(randint(lower_bound, upper_bound), width=num_chars)

	def decrypt_data(self, data, key):
		decrypted_data = b64decode(data)
		cipher= AES.new(key, AES.MODE_CBC, data[0 : self.BLOCK_SIZE].encode("UTF-8"))
		unpaded_data = self.unpad_pkcs5(cipher.decrypt(decrypted_data)[16:])
		decoded_data = unpaded_data.decode("UTF-8")
		return json.loads(decoded_data)