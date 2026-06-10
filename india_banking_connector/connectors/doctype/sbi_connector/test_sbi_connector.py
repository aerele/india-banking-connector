# Copyright (c) 2026, Aerele Technologies Private Limited and Contributors
# See license.txt

from frappe.tests.utils import FrappeTestCase

import frappe

from india_banking_connector.connectors.doctype.sbi_connector.sbi_connector import (
	SBIConnector,
)


class TestSBIConnector(FrappeTestCase):
	def get_connector(self):
		connector = frappe.get_doc(
			{
				"doctype": "SBI Connector",
				"account_number": "30096039283",
				"source_id": "CMPND",
				"corporate_code": "85002456640",
				"corporate_product_code": "CMPNDH2HAPI001",
				"base_url": "https://eissiwebuat.sbi.bank.in",
			}
		)
		connector.payment_doc = frappe._dict(
			{
				"name": "PAY-ORD-SUM-0001",
				"amount": 100,
				"branch_code": "SBIN0000001",
				"mode_of_transfer": "NEFT",
				"bank_account_no": "30095939296",
				"party_name": "UAT Test Beneficiary",
				"party": "Supplier A",
				"summary_references": "['REF-ROW-0001']",
				"parent": "PMO-00001",
			}
		)
		connector.doc = frappe._dict(
			{
				"references": [
					{
						"name": "REF-ROW-0001",
						"reference_name": "PUR-ORD-2026-00011",
					}
				]
			}
		)
		connector.compute_hash = lambda inner_request: "HASH"
		return connector

	def test_generate_request_reference_number_for_five_character_source(self):
		connector = self.get_connector()

		request_reference_number = connector.generate_request_reference_number()

		self.assertEqual(len(request_reference_number), 25)
		self.assertTrue(request_reference_number.startswith("SBICMPND"))

	def test_aes_gcm_encrypt_decrypt_roundtrip(self):
		connector = self.get_connector()
		key = connector.generate_aes_key()
		plaintext = '{"SOURCE_ID":"CMPND"}'

		encrypted = connector.aes_gcm_encrypt(plaintext, key)
		decrypted = connector.aes_gcm_decrypt(encrypted, key)

		self.assertEqual(decrypted, plaintext)

	def test_status_mapping_matches_india_banking_expected_values(self):
		connector = self.get_connector()

		self.assertEqual(
			connector.get_payment_status_from_sbi("PROCESSED")[0], "Processed"
		)
		self.assertEqual(
			connector.get_payment_status_from_sbi("REJECTED")[0], "Rejected"
		)
		self.assertEqual(connector.get_payment_status_from_sbi("FAILED")[0], "Failed")
		self.assertEqual(
			connector.get_payment_status_from_sbi("PROCESSING")[0], "Pending"
		)
		self.assertEqual(
			connector.get_payment_status_from_sbi(
				"NO SUCH TRANSACTION DETAIL FOUND"
			)[0],
			"Failed",
		)
		self.assertEqual(
			connector.get_payment_status_from_sbi("PARTIALLY SUCESSFUL")[0],
			"Processed",
		)
		self.assertEqual(
			connector.get_payment_status_from_sbi("PENDING FOR RELEASE")[0],
			"Pending",
		)

	def test_payment_payload_shape(self):
		connector = self.get_connector()

		payload = connector.get_account_config("make_payment")
		creation_request = payload["EIS_PAYLOAD"]["TransactionCreationRequest"]

		self.assertEqual(payload["SOURCE_ID"], "CMPND")
		self.assertEqual(payload["TXN_TYPE"], "PAYMENT")
		self.assertEqual(payload["TXN_SUB_TYPE"], "POSTING")
		self.assertEqual(payload["EIS_PAYLOAD"]["HASH"], "HASH")
		self.assertEqual(creation_request["corporateCode"], "85002456640")
		self.assertEqual(creation_request["corporateProductCode"], "CMPNDH2HAPI001")
		self.assertEqual(len(creation_request["uniqueRequestId"]), 11)
		self.assertEqual(
			creation_request["transactionDetails"][0]["corporateRefNo"],
			connector.get_corporate_ref_no(),
		)
		self.assertEqual(
			creation_request["transactionDetails"][0]["paymentMethodName"], "NEFT"
		)
		self.assertEqual(
			creation_request["transactionDetails"][0]["paymentInstruction1"],
			"PURORD202600011",
		)

	def test_enquiry_payload_uses_original_posting_request_id(self):
		connector = self.get_connector()

		payload = connector.get_account_config("payment_status")
		enquiry_request = payload["EIS_PAYLOAD"]["TransactionEnquiryRequest"]

		self.assertEqual(payload["TXN_SUB_TYPE"], "ENQUIRY")
		self.assertEqual(
			enquiry_request["transactionRequestId"],
			connector.get_unique_request_id(connector.payment_doc, "make_payment"),
		)
		self.assertEqual(
			enquiry_request["uniqueRequestId"],
			connector.get_unique_request_id(connector.payment_doc, "payment_status"),
		)
		self.assertEqual(
			enquiry_request["transactionRefNo"], connector.get_corporate_ref_no()
		)

	def test_status_response_uses_transaction_level_error(self):
		connector = self.get_connector()
		res_dict = frappe._dict()
		eis_response = {
			"TransactionEnquiryResponse": {
				"batchStatus": "FAILED",
				"responseMessage": "SUCCESS",
				"transactionEnquiryDetails": [
					{
						"transactionRefNo": connector.get_corporate_ref_no(),
						"status": "FAILED",
						"errorMessage": "Invalid field value paymentInstruction1 - ",
					}
				],
			}
		}

		connector.format_status_response(eis_response, res_dict)

		self.assertEqual(
			res_dict.summary_details[connector.payment_doc.name]["status"], "Failed"
		)
		self.assertEqual(
			res_dict.summary_details[connector.payment_doc.name]["message"],
			"Invalid field value paymentInstruction1 - ",
		)
