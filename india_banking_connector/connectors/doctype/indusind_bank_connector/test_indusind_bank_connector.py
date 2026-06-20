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
		self.assertNotIn("IblAcctNo", row)

	def test_a2a_row_uses_iblacctno_not_ifsc(self):
		row = self.connector._payment_row(
			{"name": "POS-2", "amount": 200, "mode_of_transfer": "A2A/FT/Internal", "branch_code": "IGNORED", "bank_account_no": "222", "party_name": "Vendor B"}
		)
		self.assertEqual(row["tranType"], "IFTO")
		self.assertEqual(row["IblAcctNo"], "222")
		self.assertNotIn("benIFSC", row)
		self.assertNotIn("benAcctNo", row)

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

		with patch("requests.post", return_value=fake_response(status_body)):
			result = self.connector.get_payment_status()

		self.assertEqual(result.payment_status, "PROCESSED")
		self.assertEqual(
			result.summary_details["POS-STATUS-1"],
			{"status": "Processed", "utr_number": "UTR123", "message": "Success"},
		)

	def test_get_bank_balance_and_statement_are_unsupported(self):
		with self.assertRaises(frappe.ValidationError):
			self.connector.get_bank_balance()
		with self.assertRaises(frappe.ValidationError):
			self.connector.get_bank_statement()
