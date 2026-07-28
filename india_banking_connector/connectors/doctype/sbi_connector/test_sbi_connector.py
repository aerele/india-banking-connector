# Copyright (c) 2026, Aerele Technologies Private Limited and Contributors
# See license.txt

import json

from frappe.tests.utils import FrappeTestCase

import frappe


class _FakeResponse:
	"""Minimal stand-in for a requests.Response for connector tests."""

	def __init__(self, payload, ok=True):
		self._payload = payload
		self.ok = ok
		self.text = json.dumps(payload) if isinstance(payload, dict) else str(payload)

	def json(self):
		return self._payload

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
		connector.compute_hash = lambda inner_request, sanitize=False: "HASH"
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

	def test_sanitize_hash_strips_forbidden_characters(self):
		connector = self.get_connector()

		cleaned = connector.sanitize_hash("abc=+/def<>;=:=(ghi==")
		for ch in ("<", ">", ";", "="):
			self.assertNotIn(ch, cleaned)
		self.assertEqual(cleaned, "abc+/def:(ghi")
		# base64 padding removed, but "+"/"/" content preserved
		self.assertEqual(connector.sanitize_hash("QQ+//w=="), "QQ+//w")

	def test_account_hash_is_sanitized_but_payment_is_not(self):
		connector = self.get_connector()
		captured = {}
		connector.compute_hash = (
			lambda inner_request, sanitize=False: captured.update({"sanitize": sanitize})
			or "HASH"
		)

		connector.get_account_config("bank_balance")
		self.assertTrue(captured["sanitize"])

		connector.doc = frappe._dict({"from_date": "01-12-2024", "to_date": "02-12-2024"})
		connector.get_account_config("bank_statement")
		self.assertTrue(captured["sanitize"])

		connector.get_account_config("make_payment")
		self.assertFalse(captured["sanitize"])

		connector.get_account_config("payment_status")
		self.assertFalse(captured["sanitize"])

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

	def test_balance_payload_shape(self):
		connector = self.get_connector()

		payload = connector.get_account_config("bank_balance")
		balance_request = payload["EIS_PAYLOAD"]["AccountBalanceRequest"]

		self.assertEqual(payload["TXN_TYPE"], "ACCOUNT")
		self.assertEqual(payload["TXN_SUB_TYPE"], "BALANCE")
		self.assertEqual(payload["EIS_PAYLOAD"]["HASH"], "HASH")
		self.assertEqual(balance_request["accountNo"], "30096039283")
		self.assertEqual(balance_request["corporateCode"], "85002456640")
		self.assertNotIn("REQUEST_REFERENCE_NUMBER", payload)

	def test_statement_payload_uses_ddmmyyyy_dates(self):
		connector = self.get_connector()
		# india_banking default fallback sends day-first %d-%m-%Y format
		connector.doc = frappe._dict(
			{"from_date": "01-12-2024", "to_date": "02-12-2024"}
		)

		payload = connector.get_account_config("bank_statement")
		statement_request = payload["EIS_PAYLOAD"]["AccountStatementRequest"]

		self.assertEqual(payload["TXN_TYPE"], "ACCOUNT")
		self.assertEqual(payload["TXN_SUB_TYPE"], "STATEMENT")
		self.assertEqual(statement_request["accountNo"], "30096039283")
		self.assertEqual(statement_request["corporateCode"], "85002456640")
		self.assertEqual(statement_request["fromDate"], "01122024")
		self.assertEqual(statement_request["toDate"], "02122024")
		# Plain request must NOT carry REQUEST_REFERENCE_NUMBER (outer-wrapper only).
		self.assertNotIn("REQUEST_REFERENCE_NUMBER", payload)

	def test_encrypted_payload_keeps_rrn_in_outer_wrapper_only(self):
		connector = self.get_connector()
		connector.digital_sign = lambda data: "SIGN"
		captured = {}

		def capture(plain, key):
			captured["plain"] = plain
			return "ENC"

		connector.aes_gcm_encrypt = capture

		wrapper = connector.get_encrypted_payload(method="bank_balance")

		# Outer wrapper carries the 25-char reference number + encrypted body + signature
		self.assertEqual(len(wrapper["REQUEST_REFERENCE_NUMBER"]), 25)
		self.assertEqual(wrapper["REQUEST"], "ENC")
		self.assertEqual(wrapper["DIGI_SIGN"], "SIGN")
		# The encrypted plain request (what we sign+encrypt) must NOT contain the RRN
		self.assertNotIn("REQUEST_REFERENCE_NUMBER", captured["plain"])

	def test_statement_date_handles_iso_and_day_first(self):
		connector = self.get_connector()
		# Bank Statements dialog date picker sends ISO yyyy-mm-dd
		self.assertEqual(connector.get_statement_date("2024-12-02"), "02122024")
		# india_banking default fallback sends day-first dd-mm-yyyy
		self.assertEqual(connector.get_statement_date("02-12-2024"), "02122024")
		# both must resolve to the SAME calendar day, never swap day/month
		self.assertEqual(
			connector.get_statement_date("2024-12-02"),
			connector.get_statement_date("02-12-2024"),
		)
		# a date object should pass through unchanged
		import datetime as _dt

		self.assertEqual(
			connector.get_statement_date(_dt.date(2024, 12, 2)), "02122024"
		)

	def test_balance_response_parses_signed_amount(self):
		connector = self.get_connector()
		res_dict = frappe._dict()
		eis_response = {
			"accountNo": "00000030095698613",
			"availableAmount": "+107000645.81",
			"responseStatus": "0",
			"errorCode": None,
			"errorDescription": None,
		}

		connector.format_balance_response(eis_response, res_dict)

		self.assertEqual(res_dict.server_status, "Success")
		self.assertEqual(res_dict.balance, 107000645.81)

	def test_balance_response_failure_sets_message(self):
		connector = self.get_connector()
		res_dict = frappe._dict()
		eis_response = {
			"responseStatus": "1",
			"errorCode": "SI570",
			"errorDescription": "BIT MAPPING NOT CONFIGURED",
		}

		connector.format_balance_response(eis_response, res_dict)

		self.assertEqual(res_dict.server_status, "Failed")
		self.assertEqual(res_dict.message, "BIT MAPPING NOT CONFIGURED")

	def test_statement_response_maps_transactions(self):
		connector = self.get_connector()
		res_dict = frappe._dict()
		eis_response = {
			"responseStatus": "0",
			"accountStatementDetails": [
				{
					"VALUE_DATE": "02/12/2024",
					"AMOUNT": "1001.69-",
					"BALANCE": "498997.30",
					"NARRATION": "TO TRANSFER",
					"STATEMENT": "CMPIFTP/25110724008/242580040005/PMT",
					"RECORD_NUMBER": "999999995",
				},
				{
					"VALUE_DATE": "02/12/2024",
					"AMOUNT": "5000.00",
					"BALANCE": "503997.30",
					"NARRATION": "BY TRANSFER",
					"STATEMENT": "CMPIFTP/01021224028/242580040007/PMT",
					"RECORD_NUMBER": "999999996",
				},
			],
		}

		connector.format_statement_response(eis_response, res_dict)

		self.assertEqual(res_dict.server_status, "Success")
		self.assertEqual(len(res_dict.bank_statements), 2)

		debit = res_dict.bank_statements[0]
		self.assertEqual(debit["transaction_amount"], -1001.69)
		self.assertEqual(str(debit["transaction_date"]), "2024-12-02")
		self.assertEqual(
			debit["reference_number"], "CMPIFTP/25110724008/242580040005/PMT"
		)
		self.assertEqual(debit["transaction_description"], "TO TRANSFER")

		credit = res_dict.bank_statements[1]
		self.assertEqual(credit["transaction_amount"], 5000.00)

	def test_statement_response_empty_and_single_dict(self):
		connector = self.get_connector()

		# no transactions -> empty list, still a success
		res_dict = frappe._dict()
		connector.format_statement_response(
			{"responseStatus": "0", "accountStatementDetails": []}, res_dict
		)
		self.assertEqual(res_dict.server_status, "Success")
		self.assertEqual(res_dict.bank_statements, [])

		# a single transaction may arrive as a dict, not a list
		res_dict = frappe._dict()
		connector.format_statement_response(
			{
				"responseStatus": "0",
				"accountStatementDetails": {
					"VALUE_DATE": "02/12/2024",
					"AMOUNT": "10.00-",
					"STATEMENT": "REF1",
				},
			},
			res_dict,
		)
		self.assertEqual(len(res_dict.bank_statements), 1)
		self.assertEqual(res_dict.bank_statements[0]["transaction_amount"], -10.0)

	def test_balance_zero_and_negative(self):
		connector = self.get_connector()

		res_dict = frappe._dict()
		connector.format_balance_response(
			{"responseStatus": "0", "availableAmount": "+0.00"}, res_dict
		)
		self.assertEqual(res_dict.balance, 0)

		res_dict = frappe._dict()
		connector.format_balance_response(
			{"responseStatus": "0", "availableAmount": "-250.50"}, res_dict
		)
		self.assertEqual(res_dict.balance, -250.50)

	def test_get_decrypted_response_balance_end_to_end(self):
		# An unencrypted response (no RESPONSE tag) flows straight through
		# process_response, exercising the full decrypt->format wiring.
		connector = self.get_connector()
		payload = {
			"RESPONSE_STATUS": "0",
			"EIS_RESPONSE": {
				"availableAmount": "+107000645.81",
				"responseStatus": "0",
			},
		}

		res = connector.get_decrypted_response(
			_FakeResponse(payload), method="bank_balance", log_id=None
		)

		self.assertEqual(res.server_status, "Success")
		self.assertEqual(res.balance, 107000645.81)

	def test_get_decrypted_response_handles_http_failure(self):
		connector = self.get_connector()

		res = connector.get_decrypted_response(
			_FakeResponse({"error": "boom"}, ok=False),
			method="bank_balance",
			log_id=None,
		)

		# Not "Success" -> india_banking surfaces a Balance Fetch Failed message
		self.assertEqual(res.status, "Request Failure")
		self.assertNotEqual(res.get("server_status"), "Success")

	def test_get_decrypted_response_wrapper_failure_sets_server_status(self):
		connector = self.get_connector()
		payload = {
			"RESPONSE_STATUS": "1",
			"ERROR_DESCRIPTION": "EIS APPLICATION INACTIVE",
		}

		res = connector.get_decrypted_response(
			_FakeResponse(payload), method="bank_statement", log_id=None
		)

		self.assertEqual(res.server_status, "Failed")
		self.assertEqual(res.message, "EIS APPLICATION INACTIVE")
