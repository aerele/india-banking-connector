# Copyright (c) 2024, Aerele Technologies Private Limited and Contributors
# See license.txt

import tempfile
from base64 import b64encode

import frappe
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from frappe.tests.utils import FrappeTestCase

from india_banking_connector.connectors.bank_connector import BankConnector
from india_banking_connector.connectors.doctype.icici_connector.icici_connector import (
	ICICIConnector,
)


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

	def format_make_payment(self, data):
		connector = object.__new__(ICICIConnector)
		connector.bulk_transaction = 0
		connector.payment_doc = frappe._dict(name="row-1")
		res_dict = frappe._dict()
		connector.get_formated_response(data, res_dict, "make_payment")
		return res_dict

	def test_make_payment_failure_reply_stays_accepted_with_bank_message(self):
		for error_code, text in (
			("106910", "Transaction with Reference ID 2569126132 failed during processing due to Invalid Beneficiary IFSCCODE or NBIN."),
			("103354", "Invalid Bank/Branch Identifier or network. Please select a valid input and try again."),
			("103068", "The transaction with Reference id 2519743852 has been submitted successfully. Please do not re-initiate, check the status of the transaction after 15 minutes."),
		):
			with self.subTest(error_code=error_code):
				res = self.format_make_payment({
					"MESSAGE": text, "ERRORCODE": error_code, "STATUS": "PENDING", "RESPONSE": "FAILURE",
				})
				self.assertEqual(res.payment_status, "ACCEPTED")
				self.assertEqual(res.message, text)
				self.assertEqual(res.summary_details, {"row-1": {"payment_status": "Accepted", "message": text}})

	def test_make_payment_success_is_accepted(self):
		res = self.format_make_payment({"STATUS": "SUCCESS", "RESPONSE": "SUCCESS", "UTRNUMBER": "624415243105"})
		self.assertEqual(res.payment_status, "ACCEPTED")
		self.assertEqual(res.summary_details, {"row-1": {"payment_status": "Accepted"}})
