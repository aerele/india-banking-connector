# Copyright (c) 2026, Aerele Technologies Private Limited and Contributors
# See license.txt

import hashlib
import hmac
import json
from base64 import b64decode, b64encode
from unittest.mock import patch

import frappe
import requests
from Crypto.Cipher import AES
from frappe.tests.utils import FrappeTestCase

AES_KEY_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
AES_IV_HEX = "000102030405060708090a0b0c0d0e0f"
TEST_ACCOUNT_NUMBER = "TESTACC001"


def get_test_connector(**fields):
	return frappe.get_doc(
		{
			"doctype": "IndusInd Bank Connector",
			"account_number": TEST_ACCOUNT_NUMBER,
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


def fake_response(body: dict, status_code: int = 200) -> requests.Response:
	"""A real requests.Response (create_api_log requires isinstance(res, Response))."""
	resp = requests.Response()
	resp.status_code = status_code
	resp._content = json.dumps(body).encode()
	req = requests.PreparedRequest()
	req.prepare(method="POST", url="https://uat.indusind.example/batch", headers={}, data="{}")
	resp.request = req
	return resp


def payment_order(name, summary_rows):
	return frappe._dict(
		{
			"doctype": "Payment Order",
			"name": name,
			"total": sum(row["amount"] for row in summary_rows),
			"summary": [frappe._dict(row) for row in summary_rows],
		}
	)


class TestIndusIndBankConnectorCrypto(FrappeTestCase):
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
		# HMAC key is the 64-char hex key STRING as literal ASCII bytes (not the
		# 32 raw bytes AES uses), and the digest is base64, not hex - per the
		# bank's actual convention confirmed against a live UAT response.
		plain = json.dumps({"a": 1}, separators=(",", ":"))
		expected = b64encode(
			hmac.new(AES_KEY_HEX.encode(), plain.encode(), hashlib.sha256).digest()
		).decode()
		self.assertEqual(self.connector._hash(plain), expected)

	def test_envelope_uses_lowercase_keys_for_posting(self):
		envelope = self.connector._envelope({"a": 1}, lower=True)
		self.assertEqual(set(envelope.keys()), {"requestMsg", "requestHash"})

	def test_envelope_uses_uppercase_keys_for_beneficiary_request(self):
		envelope = self.connector._envelope({"a": 1}, lower=False)
		self.assertEqual(set(envelope.keys()), {"RequestMsg", "RequestHash"})

	def test_envelope_hash_matches_serialized_body(self):
		body = {"b": 2, "a": 1}
		plain = json.dumps(body, separators=(",", ":"))
		envelope = self.connector._envelope(body, lower=True)
		self.assertEqual(envelope["requestHash"], self.connector._hash(plain))


class TestIndusIndBankConnectorPayloadBuilders(FrappeTestCase):
	def setUp(self):
		self.connector = get_test_connector()
		self.connector.account_number = TEST_ACCOUNT_NUMBER

	def test_neft_row_uses_ifsc_and_account_number(self):
		row = self.connector._payment_row(
			{"name": "POS-1", "amount": 100, "mode_of_transfer": "NEFT", "branch_code": "INDB0000123", "bank_account_no": "111", "party_name": "Vendor A"}
		)
		self.assertEqual(row["tranType"], "NEFT")
		self.assertEqual(row["benIFSC"], "INDB0000123")
		self.assertEqual(row["benAcctNo"], "111")

	def test_a2a_row_blanks_ifsc_but_keeps_account_number(self):
		# Per the bank's BatchPostingReqResp sample: IFTO sends benIFSC="" while
		# benAcctNo stays populated. IblAcctNo only appears in beneficiary
		# registration, never in the per-transaction payment row.
		row = self.connector._payment_row(
			{"name": "POS-2", "amount": 200, "mode_of_transfer": "A2A/FT/Internal", "branch_code": "IGNORED", "bank_account_no": "222", "party_name": "Vendor B"}
		)
		self.assertEqual(row["tranType"], "IFTO")
		self.assertEqual(row["benIFSC"], "")
		self.assertEqual(row["benAcctNo"], "222")
		self.assertNotIn("IblAcctNo", row)

	def test_unknown_mode_defaults_to_neft(self):
		self.assertEqual(self.connector._tran_type("Cheque"), "NEFT")

	def test_format_payment_response_accepted(self):
		self.connector.doc = payment_order("PO-1", [{"name": "POS-1", "amount": 1}])
		res = frappe._dict()
		self.connector._format_payment_response(
			{"StatusCode": "R000", "StatusDesc": "Batch Received"}, res
		)
		self.assertEqual(res.payment_status, "ACCEPTED")
		self.assertEqual(res.summary_details, {"POS-1": {"payment_status": "Accepted"}})

	def test_format_payment_response_rejected(self):
		self.connector.doc = payment_order("PO-2", [{"name": "POS-2", "amount": 1}])
		res = frappe._dict()
		self.connector._format_payment_response(
			{"StatusCode": "R001", "StatusDesc": "Invalid Batch"}, res
		)
		self.assertEqual(res.payment_status, "FAILED")
		self.assertEqual(res.summary_details, {"POS-2": {"payment_status": "Failed"}})

	def test_format_payment_status_response_maps_codes(self):
		res = frappe._dict()
		self.connector._format_payment_status_response(
			{
				"PayResp": {
					"Transaction": [
						{"CustRefNo": "POS-1", "StatusCode": "S", "StatusDesc": "Success", "UTR": "UTR1"},
						{"CustRefNo": "POS-2", "StatusCode": "SP", "StatusDesc": "Suspect"},
						{"CustRefNo": "POS-3", "StatusCode": "R", "StatusDesc": "Rejected by bank"},
					]
				}
			},
			res,
		)
		self.assertEqual(res.payment_status, "PROCESSED")
		self.assertEqual(res.summary_details["POS-1"], {"status": "Processed", "utr_number": "UTR1", "message": "Success"})
		self.assertEqual(res.summary_details["POS-2"]["status"], "Pending")
		self.assertEqual(res.summary_details["POS-3"]["status"], "Rejected")


class TestIndusIndBankConnectorAgainstRealUATSamples(FrappeTestCase):
	"""Each test below is transcribed verbatim from the bank's UAT sample .txt files
	(BatchPostingReqResp, BatchEnquiryReqRes, BeneAdditionRequestResponse,
	BeneEnquiryRequestResponse) so a wire-format regression fails loudly."""

	def setUp(self):
		self.connector = get_test_connector()
		self.connector.account_number = "200999514476"
		self.connector.customer_id = "31202366"
		self.connector.maker_id = "rakm"
		self.connector.checker_id = "rakc1"

	def test_transaction_posting_request_matches_bank_sample_shape(self):
		self.connector.doc = payment_order(
			"BATCH1404",
			[
				{"name": "0514973", "amount": 200, "mode_of_transfer": "IMPS", "branch_code": "SYNB0008538", "bank_account_no": "88888455", "party_name": "Amit Kumar"},
				{"name": "0514988", "amount": 200, "mode_of_transfer": "NEFT", "branch_code": "SYNB0008538", "bank_account_no": "88888455", "party_name": "Amit Kumar"},
				{"name": "0614004", "amount": 200, "mode_of_transfer": "A2A/FT/Internal", "branch_code": "SYNB0008538", "bank_account_no": "88888455", "party_name": "Amit Kumar"},
			],
		)
		self.connector.update_account_config("make_payment")
		body = self.connector.account_config["body"]["multiPayReq"]
		payments = body["body"]["payment"]

		# batchCount/batchAmount are sent as JSON strings ("3"/"600") in the
		# sample, while each row's amount is a raw JSON number (200, not "200").
		self.assertEqual(body["header"]["batchCount"], "3")
		self.assertIsInstance(body["header"]["batchAmount"], str)
		self.assertIsInstance(payments[0]["amount"], int)

		self.assertEqual([p["tranType"] for p in payments], ["IMPS", "NEFT", "IFTO"])
		self.assertEqual([p["custRefNo"] for p in payments], ["0514973", "0514988", "0614004"])
		for p in payments:
			self.assertEqual(p["benName"], "Amit Kumar")
			self.assertEqual(p["benAcctNo"], "88888455")
		self.assertEqual(payments[0]["benIFSC"], "SYNB0008538")
		self.assertEqual(payments[2]["benIFSC"], "")  # IFTO: blank per sample

	def test_transaction_posting_accepts_bank_sample_response(self):
		ack = {"BatchRefNo": "DXK6040321066826", "TxnCount": "10", "StatusCode": "R000", "StatusDesc": "Batch Received"}
		self.connector.doc = payment_order("BATCH1404", [{"name": "0514973", "amount": 200}])
		res = frappe._dict()
		self.connector._format_payment_response(ack, res)
		self.assertEqual(res.payment_status, "ACCEPTED")
		self.assertEqual(res.message, "Batch Received")

	def test_transaction_enquiry_request_matches_bank_sample_shape(self):
		self.connector.doc = payment_order("BAPI280421067549", [])
		self.connector.update_account_config("payment_status")
		self.assertEqual(
			self.connector.account_config["body"],
			{"Customerid": "31202366", "RefNo": "BAPI280421067549", "IsBatch": "Y"},
		)

	def test_transaction_enquiry_maps_bank_sample_response(self):
		# Verbatim from BatchEnquiryReqRes.txt
		sample_response = {
			"PayResp": {
				"Header": {"RefNo": "BAPI280421067549", "IsBatch": "Y", "TxnCount": "3", "Error": ""},
				"Transaction": [
					{"IBLRefNo": "DAL4280421000029", "CustRefNo": "0514973", "StatusCode": "UP", "StatusDesc": "Authorized/Under Processing", "UTR": "", "PaymentDate": "", "BeneficiaryName": ""},
					{"IBLRefNo": "DAL4280421000030", "CustRefNo": "0514988", "StatusCode": "S", "StatusDesc": "Success", "UTR": "INDBN28044772077", "PaymentDate": "2021-04-28", "BeneficiaryName": ""},
					{"IBLRefNo": "DAL4280421000031", "CustRefNo": "0614004", "StatusCode": "J", "StatusDesc": "Account does not exist", "UTR": "", "PaymentDate": "", "BeneficiaryName": ""},
				],
			}
		}
		res = frappe._dict()
		self.connector._format_payment_status_response(sample_response, res)

		self.assertEqual(res.summary_details["0514973"]["status"], "Pending")  # UP, never final
		self.assertEqual(res.summary_details["0514988"], {"status": "Processed", "utr_number": "INDBN28044772077", "message": "Success"})
		self.assertEqual(res.summary_details["0614004"], {"status": "Failed", "utr_number": "", "message": "Account does not exist"})

	def test_beneficiary_request_matches_bank_sample_shape(self):
		self.connector._beneficiaries = [
			{"req_mode": "A", "tran_type": "IMPS,NEFT,RTGS", "ben_code": "BT752", "ben_name": "Amit Kumar", "ben_ifsc": "SYNB0008538", "ben_acct_no": "88888455", "ben_email": "amita.kumar@indusind.com", "ben_mobile": "639999512"},
			{"req_mode": "A", "tran_type": "IFTO", "ben_code": "BN893", "ben_name": "Amit Kumar", "ibl_acct_no": "123456", "ben_email": "amita.kumar@indusind.com", "ben_mobile": "639999512"},
		]
		self.connector._beneficiary_batch_id = "BATCH897"
		self.connector.update_account_config("beneficiary_request")

		bene_list = self.connector.account_config["body"]["MultiBeneReq"]["Body"]["BeneList"]
		self.assertEqual(bene_list[0]["TranType"], "IMPS,NEFT,RTGS")
		self.assertEqual(bene_list[0]["BenIFSC"], "SYNB0008538")
		self.assertEqual(bene_list[0]["BenAcctNo"], "88888455")
		self.assertEqual(bene_list[0]["IblAcctNo"], "")

		self.assertEqual(bene_list[1]["TranType"], "IFTO")
		self.assertEqual(bene_list[1]["BenIFSC"], "")
		self.assertEqual(bene_list[1]["BenAcctNo"], "")
		self.assertEqual(bene_list[1]["IblAcctNo"], "123456")

	def test_beneficiary_request_accepts_bank_sample_response(self):
		ack = {"BatchRefNo": "A31O210521068040", "BeneCount": "2", "StatusCode": "R000", "StatusDesc": "Batch Received"}
		res = frappe._dict()
		self.connector._format_beneficiary_request_response(ack, res)
		self.assertEqual(res.status, "Accepted")

	def test_beneficiary_enquiry_request_matches_bank_sample_shape(self):
		self.connector._beneficiary_ref_no = "A31O100521067968"
		self.connector.customer_id = "32701183"
		self.connector.update_account_config("beneficiary_enquiry")
		self.assertEqual(
			self.connector.account_config["body"],
			{"Customerid": "32701183", "RefNo": "A31O100521067968", "IsBatch": "Y"},
		)

	def test_beneficiary_enquiry_maps_bank_sample_response(self):
		# Verbatim from BeneEnquiryRequestResponse.txt
		sample_response = {
			"BeneResp": {
				"Header": {"RefNo": "A31O100521067968", "IsBatch": "Y", "BeneCount": "1", "Error": ""},
				"BeneList": [
					{"BenCode": "BE118", "BenName": "Amit Kumar", "BenIFSC": "HDFC0000501", "BenAcctNo": "579625252415", "IblAcctNo": "", "StatusCode": "I", "StatusDesc": "InActive"}
				],
			}
		}
		res = frappe._dict()
		self.connector._format_beneficiary_enquiry_response(sample_response, res)
		self.assertEqual(res.status, "Fetched")
		self.assertEqual(res.beneficiaries["BE118"], {"status": "Inactive", "message": "InActive"})


class TestIndusIndBankConnectorOperations(FrappeTestCase):
	def setUp(self):
		frappe.db.delete("IndusInd Bank Connector", {"account_number": TEST_ACCOUNT_NUMBER})
		self.connector = get_test_connector()
		self.connector.insert(ignore_permissions=True)
		frappe.db.commit()

	def tearDown(self):
		frappe.db.delete("Bank Request Log", {"connector_name": self.connector.name})
		frappe.delete_doc("IndusInd Bank Connector", self.connector.name, force=True, ignore_permissions=True)
		frappe.db.commit()

	def test_initiate_payment_sends_gcm_envelope_and_maps_accepted_response(self):
		self.connector.doc = payment_order(
			"PO-INIT-1",
			[{"name": "POS-INIT-1", "amount": 250, "mode_of_transfer": "NEFT", "branch_code": "INDB0000123", "bank_account_no": "111", "party_name": "Vendor A"}],
		)
		ack = {"BatchRefNo": "BR1", "TxnCount": "1", "StatusCode": "R000", "StatusDesc": "Batch Received"}

		with patch("requests.post", return_value=fake_response(ack)) as mock_post:
			result = self.connector.initiate_payment()

		sent_payload = mock_post.call_args.kwargs["json"]
		self.assertEqual(set(sent_payload.keys()), {"requestMsg", "requestHash"})
		decrypted = json.loads(self.connector._decrypt(sent_payload["requestMsg"]))
		self.assertEqual(
			decrypted["multiPayReq"]["body"]["payment"][0]["custRefNo"], "POS-INIT-1"
		)
		self.assertEqual(result.payment_status, "ACCEPTED")
		self.assertEqual(result.summary_details, {"POS-INIT-1": {"payment_status": "Accepted"}})

	def test_initiate_payment_dedupes_on_retry_without_second_http_call(self):
		self.connector.doc = payment_order(
			"PO-INIT-2",
			[{"name": "POS-INIT-2", "amount": 100, "mode_of_transfer": "IMPS", "branch_code": "INDB0000999", "bank_account_no": "222", "party_name": "Vendor B"}],
		)
		ack = {"BatchRefNo": "BR2", "TxnCount": "1", "StatusCode": "R000", "StatusDesc": "Batch Received"}

		with patch("requests.post", return_value=fake_response(ack)) as mock_post:
			self.connector.initiate_payment()
			self.assertEqual(mock_post.call_count, 1)

		retry_connector = frappe.get_doc("IndusInd Bank Connector", self.connector.name)
		retry_connector.doc = self.connector.doc
		with patch("requests.post", return_value=fake_response(ack)) as mock_post_retry:
			retry_connector.initiate_payment()
			self.assertEqual(mock_post_retry.call_count, 0)

	def test_get_payment_status_round_trips_through_real_http_mock(self):
		self.connector.doc = payment_order(
			"PO-STATUS-1",
			[{"name": "POS-STATUS-1", "amount": 100, "mode_of_transfer": "NEFT", "branch_code": "INDB0000123", "bank_account_no": "111", "party_name": "Vendor A"}],
		)
		status_body = {
			"PayResp": {
				"Transaction": [
					{"CustRefNo": "POS-STATUS-1", "StatusCode": "S", "StatusDesc": "Success", "UTR": "UTR123"}
				]
			}
		}

		with patch("requests.post", return_value=fake_response(status_body)) as mock_post:
			result = self.connector.get_payment_status()

		# Per the H2H doc, TransactionEnquiry uses RequestMsg/RequestHash
		# (uppercase) unlike TransactionPosting.
		self.assertEqual(set(mock_post.call_args.kwargs["json"].keys()), {"RequestMsg", "RequestHash"})
		self.assertEqual(result.payment_status, "PROCESSED")
		self.assertEqual(
			result.summary_details["POS-STATUS-1"],
			{"status": "Processed", "utr_number": "UTR123", "message": "Success"},
		)

	def test_get_payment_status_decrypts_encrypted_response(self):
		# Confirmed against live UAT: IndusInd encrypts responses too, unlike
		# the H2H doc's plaintext response samples.
		self.connector.doc = payment_order(
			"PO-STATUS-2",
			[{"name": "POS-STATUS-2", "amount": 100, "mode_of_transfer": "NEFT", "branch_code": "INDB0000123", "bank_account_no": "111", "party_name": "Vendor A"}],
		)
		plain = json.dumps({"PayResp": {"Transaction": [{"CustRefNo": "POS-STATUS-2", "StatusCode": "S", "StatusDesc": "Success", "UTR": "UTR999"}]}})
		encrypted_body = {"responseMsg": self.connector._encrypt(plain), "responseHash": self.connector._hash(plain)}

		with patch("requests.post", return_value=fake_response(encrypted_body)):
			result = self.connector.get_payment_status()

		self.assertEqual(result.payment_status, "PROCESSED")
		self.assertEqual(result.summary_details["POS-STATUS-2"]["utr_number"], "UTR999")

	def test_get_payment_status_reports_failure_on_undecryptable_response(self):
		self.connector.doc = payment_order("PO-STATUS-3", [{"name": "POS-STATUS-3", "amount": 100}])
		bad_body = {"responseMsg": "not-valid-base64-gcm-ciphertext==", "responseHash": "irrelevant"}

		with patch("requests.post", return_value=fake_response(bad_body)):
			result = self.connector.get_payment_status()

		self.assertEqual(result.status, "Request Failure")

	def test_add_beneficiaries_sends_uppercase_envelope(self):
		ack = {"BatchRefNo": "BR3", "BeneCount": "1", "StatusCode": "R000", "StatusDesc": "Batch Received"}
		beneficiaries = [{"ben_code": "BT1", "tran_type": "NEFT", "ben_name": "Vendor A", "ben_ifsc": "INDB0000123", "ben_acct_no": "111"}]

		with patch("requests.post", return_value=fake_response(ack)) as mock_post:
			result = self.connector.add_beneficiaries(beneficiaries, batch_id="BATCH-TEST-1")

		sent_payload = mock_post.call_args.kwargs["json"]
		self.assertEqual(set(sent_payload.keys()), {"RequestMsg", "RequestHash"})
		decrypted = json.loads(self.connector._decrypt(sent_payload["RequestMsg"]))
		self.assertEqual(decrypted["MultiBeneReq"]["Header"]["BatchId"], "BATCH-TEST-1")
		self.assertEqual(result.status, "Accepted")

	def test_get_beneficiary_status_sends_uppercase_envelope(self):
		status_body = {
			"BeneResp": {
				"BeneList": [{"BenCode": "BT1", "StatusCode": "A", "StatusDesc": "Active"}]
			}
		}

		with patch("requests.post", return_value=fake_response(status_body)) as mock_post:
			result = self.connector.get_beneficiary_status("REF-1")

		sent_payload = mock_post.call_args.kwargs["json"]
		self.assertEqual(set(sent_payload.keys()), {"RequestMsg", "RequestHash"})
		self.assertEqual(result.beneficiaries["BT1"], {"status": "Active", "message": "Active"})

	def test_get_bank_balance_and_statement_are_unsupported(self):
		with self.assertRaises(frappe.ValidationError):
			self.connector.get_bank_balance()
		with self.assertRaises(frappe.ValidationError):
			self.connector.get_bank_statement()
