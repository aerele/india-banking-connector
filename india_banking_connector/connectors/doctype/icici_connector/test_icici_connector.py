# Copyright (c) 2024, Aerele Technologies Private Limited and Contributors
# See license.txt

import tempfile
from base64 import b64encode

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from frappe.tests.utils import FrappeTestCase

from india_banking_connector.connectors.bank_connector import BankConnector


class TestICICIConnector(FrappeTestCase):
	def test_response_key_decrypt_accepts_pkcs1_and_pkcs8_private_keys(self):
		key_pair = RSA.generate(2048)
		aes_key = b"AESKEY1234567890"
		encrypted_key = b64encode(
			PKCS1_v1_5.new(key_pair.publickey()).encrypt(aes_key)
		).decode("utf-8")
		connector = object.__new__(BankConnector)

		for private_key in (
			key_pair.export_key(format="PEM", pkcs=1),
			key_pair.export_key(format="PEM", pkcs=8),
		):
			with (
				self.subTest(pem_header=private_key.splitlines()[0]),
				tempfile.NamedTemporaryFile(suffix=".pem") as key_file,
			):
				key_file.write(private_key)
				key_file.flush()
				self.assertEqual(
					connector.rsa_decrypt_key(encrypted_key, key_file.name),
					aes_key.decode("utf-8"),
				)
