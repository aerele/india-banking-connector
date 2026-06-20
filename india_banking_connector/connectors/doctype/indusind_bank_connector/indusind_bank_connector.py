# Copyright (c) 2026, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

import hashlib
import hmac
import json
import re
from base64 import b64decode, b64encode

import frappe
import requests
from Crypto.Cipher import AES
from frappe import _

from india_banking_connector.connectors.bank_connector import BankConnector
from india_banking_connector.india_banking_connector.doctype.bank_request_log.bank_request_log import (
	create_api_log,
)

GCM_TAG_LENGTH = 16
POSTING_ACCEPTED_CODE = "R000"

# Mode of Transfer -> IndusInd tranType. IFTO (Internal/A2A) addresses the
# beneficiary by IblAcctNo instead of IFSC + account number.
TRAN_TYPE = {
	"imps": "IMPS",
	"neft": "NEFT",
	"rtgs": "RTGS",
	"a2a": "IFTO",
}

# IndusInd TransactionEnquiry StatusCode -> Payment Order Summary payment_status.
# SP/UP/N/P/PR/FA/SW are deliberately non-final (mapped to Pending): re-initiating
# on these causes double payments. J/F vs R/RE -> Failed/Rejected is a judgment
# call pending bank confirmation (the H2H doc groups all four as one bucket).
STATUS = {
	"S": "Processed",
	"UP": "Pending",
	"N/P": "Pending",
	"PR": "Pending",
	"SP": "Pending",
	"FA": "Pending",
	"SW": "Pending",
	"J": "Failed",
	"F": "Failed",
	"R": "Rejected",
	"RE": "Rejected",
}


class IndusIndBankConnector(BankConnector):
	bank = "IndusInd Bank"

	# IndusInd's Batch API uses AES-256-GCM + HMAC-SHA256, which the base class
	# doesn't provide (it only has CBC and JWE-wrapped GCM). Byte layout below
	# (ciphertext|tag, fixed IV from the `iv` field) is per the H2H doc and is
	# unverified against a live UAT sample — confirm before a real UAT call.

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.doc = frappe._dict(kwargs.get("doc", {}))
		self.account_config = {}

	def _aes_key(self) -> bytes:
		return bytes.fromhex(self.get_password("aes_key"))

	def _aes_iv(self) -> bytes:
		return bytes.fromhex(self.get_password("iv"))

	def _encrypt(self, plain: str) -> str:
		cipher = AES.new(self._aes_key(), AES.MODE_GCM, nonce=self._aes_iv())
		ciphertext, tag = cipher.encrypt_and_digest(plain.encode())
		return b64encode(ciphertext + tag).decode()

	def _decrypt(self, blob: str) -> str:
		raw = b64decode(blob)
		ciphertext, tag = raw[:-GCM_TAG_LENGTH], raw[-GCM_TAG_LENGTH:]
		cipher = AES.new(self._aes_key(), AES.MODE_GCM, nonce=self._aes_iv())
		return cipher.decrypt_and_verify(ciphertext, tag).decode()

	def _hash(self, plain: str) -> str:
		return hmac.new(self._aes_key(), plain.encode(), hashlib.sha256).hexdigest()

	def _envelope(self, body: dict, lower: bool) -> dict:
		plain = json.dumps(body, separators=(",", ":"))
		msg_key, hash_key = ("requestMsg", "requestHash") if lower else ("RequestMsg", "RequestHash")
		return {msg_key: self._encrypt(plain), hash_key: self._hash(plain)}

	@property
	def headers(self):
		return {
			"IBL-Client-Id": self.get_password("client_id"),
			"IBL-Client-Secret": self.get_password("client_secret"),
			"Content-Type": "application/json",
		}

	# ---- operations (poll-based: TransactionPosting ack, then TransactionEnquiry) ----

	def initiate_payment(self):
		unique_id = self._unique_id()
		if existing := self.validate_duplicate_payments(unique_id=unique_id):
			return existing

		payload = self.get_encrypted_payload("make_payment")
		response = requests.post(self.urls.make_payment, headers=self.headers, json=payload)

		log_id = create_api_log(
			response,
			action="Initiate Payment",
			account_config=self.account_config,
			ref_doctype=self.doc.doctype,
			ref_docname=self.doc.name,
			unique_id=unique_id,
			connector=self,
		)
		return self.get_decrypted_response(response, method="make_payment", log_id=log_id)

	def get_payment_status(self):
		payload = self.get_encrypted_payload("payment_status")
		response = requests.post(self.urls.payment_status, headers=self.headers, json=payload)

		log_id = create_api_log(
			response,
			action="Payment Status",
			account_config=self.account_config,
			ref_doctype=self.doc.doctype,
			ref_docname=self.doc.name,
			unique_id=self._unique_id(),
			connector=self,
		)
		return self.get_decrypted_response(response, method="payment_status", log_id=log_id)

	def get_bank_balance(self):
		frappe.throw(_("Not supported by IndusInd Batch API"))

	def get_bank_statement(self):
		frappe.throw(_("Not supported by IndusInd Batch API"))

	# ---- payload builders ----

	def get_encrypted_payload(self, method):
		self.update_account_config(method)
		return self._envelope(self.account_config["body"], lower=True)

	def update_account_config(self, method):
		{
			"make_payment": self.set_payment_data,
			"payment_status": self.set_payment_status_data,
		}[method]()

	def set_payment_data(self):
		summary = self.doc.get("summary") or []
		self.account_config["body"] = {
			"multiPayReq": {
				"header": {
					"batchId": self._unique_id(),
					"batchCount": str(len(summary)),
					"batchAmount": str(self.doc.get("total")),
					"makerId": self.maker_id,
					"checkerId": self.checker_id,
					"payMode": self.pay_mode or "I",
					"custId": self.customer_id,
					"debitAcctNumber": self.account_number,
				},
				"body": {"payment": [self._payment_row(row) for row in summary]},
			}
		}

	def _payment_row(self, row):
		row = frappe._dict(row)
		tran_type = self._tran_type(row.mode_of_transfer)

		payment = {
			"tranType": tran_type,
			"custRefNo": row.name,
			"amount": row.amount,
			"debitAcctNo": self.account_number,
			"benName": self.clean_string(row.party_name or row.party),
		}
		if tran_type == "IFTO":
			payment["IblAcctNo"] = row.bank_account_no
		else:
			payment["benIFSC"] = row.branch_code
			payment["benAcctNo"] = row.bank_account_no
		return payment

	def _tran_type(self, mode_of_transfer):
		mode = (mode_of_transfer or "").lower()
		for key, tran_type in TRAN_TYPE.items():
			if key in mode:
				return tran_type
		return "NEFT"

	def set_payment_status_data(self):
		self.account_config["body"] = {
			"Customerid": self.customer_id,
			"RefNo": self._unique_id(),
			"IsBatch": "Y",
		}

	def _unique_id(self):
		return "".join(re.findall(r"[0-9a-zA-Z]", self.doc.name))

	# ---- response -> India Banking contract ----

	def get_decrypted_response(self, response, method, log_id):
		res = frappe._dict()
		if not response.ok:
			res.status = "Request Failure"
			res.message = response.text
			return res

		data = response.json()
		self.set_decrypted_response(log_id, json.dumps(data))
		self.get_formated_response(data, res, method)
		return res

	def get_formated_response(self, data, res, method):
		if isinstance(data, str):
			data = json.loads(data)

		if method == "make_payment":
			self._format_payment_response(data, res)
		elif method == "payment_status":
			self._format_payment_status_response(data, res)

	def _format_payment_response(self, data, res):
		accepted = data.get("StatusCode") == POSTING_ACCEPTED_CODE
		res.payment_status = "ACCEPTED" if accepted else "FAILED"
		res.message = data.get("StatusDesc", "")
		res.summary_details = self.get_summary_details("Accepted" if accepted else "Failed")

	def _format_payment_status_response(self, data, res):
		transactions = data.get("PayResp", {}).get("Transaction", [])
		res.payment_status = "PROCESSED" if transactions else "Request Failure"
		res.message = (
			"Payment status fetched successfully." if transactions else "Invalid response format."
		)
		res.summary_details = {
			txn.get("CustRefNo"): {
				"status": STATUS.get(txn.get("StatusCode"), "Pending"),
				"utr_number": txn.get("UTR", ""),
				"message": txn.get("StatusDesc", ""),
			}
			for txn in transactions
		}
