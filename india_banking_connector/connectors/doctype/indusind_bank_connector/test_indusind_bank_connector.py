# Copyright (c) 2026, Aerele Technologies Private Limited and Contributors
# See license.txt

import hashlib
import hmac
import json
from base64 import b64decode, b64encode

import frappe
from Crypto.Cipher import AES
from frappe.tests.utils import FrappeTestCase

AES_KEY_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
AES_IV_HEX = "000102030405060708090a0b0c0d0e0f"


def get_test_connector(**fields):
	return frappe.get_doc(
		{
			"doctype": "IndusInd Bank Connector",
			"account_number": "TESTACC001",
			"customer_id": "CUST001",
			"maker_id": "SMAKER",
			"checker_id": "SCHECKER",
			"client_id": "test-client-id",
			"client_secret": "test-client-secret",
			"aes_key": AES_KEY_HEX,
			"iv": AES_IV_HEX,
			"base_url": "https://uat.indusind.example",
			**fields,
		}
	)


class TestIndusIndBankConnector(FrappeTestCase):
	def setUp(self):
		self.connector = get_test_connector()

	def test_encrypt_decrypt_round_trip(self):
		plain = json.dumps({"Customerid": "CUST001", "RefNo": "ABC123", "IsBatch": "Y"})
		encrypted = self.connector._encrypt(plain)
		self.assertEqual(self.connector._decrypt(encrypted), plain)

	def test_encrypt_byte_layout_is_ciphertext_then_tag(self):
		plain = "indusind-gcm-fixture"
		encrypted = self.connector._encrypt(plain)

		key = bytes.fromhex(AES_KEY_HEX)
		iv = bytes.fromhex(AES_IV_HEX)
		cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
		expected_ciphertext, expected_tag = cipher.encrypt_and_digest(plain.encode())

		raw = b64decode(encrypted)
		self.assertEqual(raw[:-16], expected_ciphertext)
		self.assertEqual(raw[-16:], expected_tag)
		self.assertEqual(encrypted, b64encode(expected_ciphertext + expected_tag).decode())

	def test_decrypt_rejects_tampered_ciphertext(self):
		encrypted = self.connector._encrypt("indusind-gcm-fixture")
		raw = bytearray(b64decode(encrypted))
		raw[0] ^= 0xFF
		tampered = b64encode(bytes(raw)).decode()
		with self.assertRaises(ValueError):
			self.connector._decrypt(tampered)

	def test_hash_matches_hmac_sha256_of_plaintext(self):
		plain = json.dumps({"a": 1}, separators=(",", ":"))
		expected = hmac.new(bytes.fromhex(AES_KEY_HEX), plain.encode(), hashlib.sha256).hexdigest()
		self.assertEqual(self.connector._hash(plain), expected)

	def test_envelope_uses_lowercase_keys_for_posting(self):
		envelope = self.connector._envelope({"a": 1}, lower=True)
		self.assertEqual(set(envelope.keys()), {"requestMsg", "requestHash"})

	def test_envelope_uses_uppercase_keys_for_beneficiary_endpoints(self):
		envelope = self.connector._envelope({"a": 1}, lower=False)
		self.assertEqual(set(envelope.keys()), {"RequestMsg", "RequestHash"})

	def test_envelope_hash_matches_serialized_body(self):
		body = {"b": 2, "a": 1}
		plain = json.dumps(body, separators=(",", ":"))
		envelope = self.connector._envelope(body, lower=True)
		self.assertEqual(envelope["requestHash"], self.connector._hash(plain))
