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
from frappe.utils import flt

from india_banking_connector.connectors.bank_connector import BankConnector
from india_banking_connector.india_banking_connector.doctype.bank_request_log.bank_request_log import (
	create_api_log,
)

GCM_TAG_LENGTH = 16

# Batch-level ack code, shared by TransactionPosting and BeneficiaryRequest
# responses. R000=Batch Received, R001=validation error (duplicate/invalid
# count/amount), R004=invalid request/hash, R005=internal server error - any
# non-R000 is surfaced as a failure via StatusDesc, so they don't need their
# own branches.
POSTING_ACCEPTED_CODE = "R000"

# Mode of Transfer -> IndusInd tranType. IFTO (Internal/A2A) is a within-bank
# transfer, so benIFSC is sent empty for it; benAcctNo is always populated.
TRAN_TYPE = {
	"imps": "IMPS",
	"neft": "NEFT",
	"rtgs": "RTGS",
	"a2a": "IFTO",
}

# IndusInd "Status Maintained for APIs" (H2H doc) -> Payment Order Summary
# payment_status. SP/UP/N-P/PR/FA/SW are deliberately non-final (mapped to
# Pending): re-initiating on these causes double payments.
STATUS = {
	"S": "Processed",  # Success
	"UP": "Pending",  # Authorized/Under Processing
	"N/P": "Pending",  # Pending for Authorization
	"PR": "Pending",  # Pending for Release
	"SP": "Pending",  # Suspect Time-out
	"FA": "Pending",  # Future dated Transaction
	"SW": "Pending",  # Scheduled for Next Applicable Day
	"J": "Failed",  # Expired / Front end validation failure
	"F": "Failed",  # Failure (Finacle / IMPS Hub)
	"RE": "Failed",  # Return (processed, then bounced back)
	"R": "Rejected",  # Rejected
}

# IndusInd Beneficiary "Status Maintained for APIs" (H2H Beneficiary doc).
BENEFICIARY_STATUS = {
	"A": "Active",
	"I": "Inactive",
	"R": "Rejected",
	"J": "Failed",
	"H": "Pending",  # account validation in process
}


class IndusIndBankConnector(BankConnector):
	bank = "IndusInd Bank"

	# IndusInd's Batch API uses AES-256-GCM + HMAC-SHA256, which the base class
	# doesn't provide (it only has CBC and JWE-wrapped GCM). Byte layout below
	# (ciphertext|tag, fixed IV from the `iv` field) confirmed against a live
	# UAT TransactionPosting round trip on 2026-06-26 (decrypted a real R005
	# response cleanly) - this was wrong until aes_key/iv were set to the
	# bank-issued values instead of the test-fixture placeholders.

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.doc = frappe._dict(kwargs.get("doc", {}))
		self.account_config = {}

	def _aes_key(self) -> bytes:
		return bytes.fromhex(self.get_password("aes_key"))

	def _aes_iv(self) -> bytes:
		return bytes.fromhex(self.get_password("iv"))

	def _hash_key(self) -> bytes:
		# The bank HMACs with the 64-char hex key string taken as literal ASCII
		# bytes, not the 32 raw bytes it decodes to for AES - confirmed by
		# matching their responseHash on a live UAT call (2026-06-27).
		return self.get_password("aes_key").encode()

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
		return b64encode(hmac.new(self._hash_key(), plain.encode(), hashlib.sha256).digest()).decode()

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

		payload = self.get_encrypted_payload("make_payment", lower=True)
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
		# Per the H2H doc, TransactionEnquiry's envelope is RequestMsg/RequestHash
		# (uppercase) - TransactionPosting is the only lowercase one.
		payload = self.get_encrypted_payload("payment_status", lower=False)
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

	@frappe.whitelist()
	def add_beneficiaries(self, beneficiaries, batch_id=None):
		"""beneficiaries: list of dicts with ben_code, tran_type, ben_name, ben_ifsc,
		ben_acct_no, ibl_acct_no, ben_email, ben_mobile, req_mode (default "A")."""
		if isinstance(beneficiaries, str):
			beneficiaries = json.loads(beneficiaries)

		self._beneficiaries = beneficiaries
		self._beneficiary_batch_id = batch_id or frappe.generate_hash(length=10)

		payload = self.get_encrypted_payload("beneficiary_request", lower=False)
		response = requests.post(self.urls.beneficiary_request, headers=self.headers, json=payload)

		log_id = create_api_log(
			response,
			action="Add Beneficiaries",
			account_config=self.account_config,
			ref_doctype=self.doctype,
			ref_docname=self.name,
			unique_id=self._beneficiary_batch_id,
			connector=self,
		)
		return self.get_decrypted_response(response, method="beneficiary_request", log_id=log_id)

	@frappe.whitelist()
	def get_beneficiary_status(self, ref_no):
		self._beneficiary_ref_no = ref_no

		payload = self.get_encrypted_payload("beneficiary_enquiry", lower=False)
		response = requests.post(self.urls.beneficiary_enquiry, headers=self.headers, json=payload)

		log_id = create_api_log(
			response,
			action="Beneficiary Status",
			account_config=self.account_config,
			ref_doctype=self.doctype,
			ref_docname=self.name,
			unique_id=ref_no,
			connector=self,
		)
		return self.get_decrypted_response(response, method="beneficiary_enquiry", log_id=log_id)

	# ---- payload builders ----

	def get_encrypted_payload(self, method, lower):
		self.update_account_config(method)
		return self._envelope(self.account_config["body"], lower=lower)

	def update_account_config(self, method):
		{
			"make_payment": self.set_payment_data,
			"payment_status": self.set_payment_status_data,
			"beneficiary_request": self.set_beneficiary_request_data,
			"beneficiary_enquiry": self.set_beneficiary_enquiry_data,
		}[method]()

	def set_payment_data(self):
		summary = self.doc.get("summary") or []
		# batchAmount must equal the sum of the payments below - self.doc.get("total")
		# isn't reliable (it was "0.0" against a real 1000.0 payment in UAT testing).
		batch_amount = sum(flt(row.get("amount")) for row in summary)
		self.account_config["body"] = {
			"multiPayReq": {
				"header": {
					"batchId": self._unique_id(),
					"batchCount": str(len(summary)),
					"batchAmount": str(batch_amount),
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
		# Prefer the mode the user actually chose in the "Initiate Payment"
		# dialog (Payment Order.default_mode_of_transfer) over the per-row
		# mode india_banking derived from its amount-slab lookup, which
		# silently overrides an explicit NEFT/RTGS choice for small amounts
		# that also fall inside IMPS's range.
		tran_type = self._tran_type(
			self.doc.get("default_mode_of_transfer") or row.mode_of_transfer
		)

		return {
			"tranType": tran_type,
			"custRefNo": row.name,
			"amount": row.amount,
			"debitAcctNo": self.account_number,
			"valueDate": "",
			"benCode": self._ben_code(row),
			"benName": self.clean_string(row.party_name or row.party),
			"benIFSC": "" if tran_type == "IFTO" else (row.branch_code or ""),
			"benAcctNo": row.bank_account_no or "",
			"benEmail": row.email or "",
			"benMobile": self._ben_mobile(row),
			"reserve1": "",
			"reserve2": "",
			"reserve3": "",
		}

	def _ben_code(self, row):
		if not row.bank_account:
			return ""
		return frappe.db.get_value("Bank Account", row.bank_account, "indusind_ben_code") or ""

	def _ben_mobile(self, row):
		if not (row.party_type and row.party):
			return ""
		meta = frappe.get_meta(row.party_type)
		for fieldname in ("mobile_no", "cell_number"):
			if meta.has_field(fieldname):
				return frappe.db.get_value(row.party_type, row.party, fieldname) or ""
		return ""

	def _tran_type(self, mode_of_transfer):
		mode = (mode_of_transfer or "").lower()
		for key, tran_type in TRAN_TYPE.items():
			if key in mode:
				return tran_type
		return "NEFT"

	def set_payment_status_data(self):
		# RefNo must be the bank-assigned BatchRefNo from the initiate-payment
		# ack, not our own batchId - IndusInd doesn't recognise the client's
		# reference for TransactionEnquiry. Fall back to the old (incorrect)
		# behaviour only for batches initiated before this field existed.
		self.account_config["body"] = {
			"Customerid": self.customer_id,
			"RefNo": self.doc.get("batch_ref_no") or self._unique_id(),
			"IsBatch": "Y",
		}

	def set_beneficiary_request_data(self):
		beneficiaries = self._beneficiaries
		self.account_config["body"] = {
			"MultiBeneReq": {
				"Header": {
					"BatchId": self._beneficiary_batch_id,
					"BatchCount": str(len(beneficiaries)),
					"MakerId": self.maker_id,
					"CheckerId": self.checker_id,
					"CustId": self.customer_id,
				},
				"Body": {"BeneList": [self._beneficiary_row(b) for b in beneficiaries]},
			}
		}

	def _beneficiary_row(self, beneficiary):
		beneficiary = frappe._dict(beneficiary)
		tran_type = beneficiary.tran_type
		if isinstance(tran_type, list):
			tran_type = ",".join(tran_type)

		return {
			"ReqMode": beneficiary.req_mode or "A",
			"TranType": tran_type or "",
			"BenCode": beneficiary.ben_code or "",
			"BenName": self.clean_string(beneficiary.ben_name),
			"BenIFSC": beneficiary.ben_ifsc or "",
			"BenAcctNo": beneficiary.ben_acct_no or "",
			"IblAcctNo": beneficiary.ibl_acct_no or "",
			"BenEmail": beneficiary.ben_email or "",
			"BenMobile": beneficiary.ben_mobile or "",
			"Reserve1": "",
			"Reserve2": "",
			"Reserve3": "",
		}

	def set_beneficiary_enquiry_data(self):
		self.account_config["body"] = {
			"Customerid": self.customer_id,
			"RefNo": self._beneficiary_ref_no,
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
		enc_key = "responseMsg" if "responseMsg" in data else "ResponseMsg" if "ResponseMsg" in data else None
		if enc_key:
			# Confirmed against live UAT (2026-06-20): IndusInd encrypts responses
			# too, contradicting the H2H doc's plaintext response samples. Byte
			# layout/key for decryption confirmed 2026-06-26 - same AES-256-GCM
			# layout as the request, same key/iv. The earlier "unconfirmed"
			# failures were caused by aes_key/iv still holding test-fixture
			# values instead of the bank-issued UAT key.
			try:
				data = json.loads(self._decrypt(data[enc_key]))
			except Exception:
				res.status = "Request Failure"
				res.message = "Response Decryption Failed - confirm responseMsg byte layout with IndusInd."
				self.set_decrypted_response(log_id, json.dumps(data))
				return res

		self.set_decrypted_response(log_id, json.dumps(data))
		self.get_formated_response(data, res, method)
		return res

	def get_formated_response(self, data, res, method):
		if isinstance(data, str):
			data = json.loads(data)

		{
			"make_payment": self._format_payment_response,
			"payment_status": self._format_payment_status_response,
			"beneficiary_request": self._format_beneficiary_request_response,
			"beneficiary_enquiry": self._format_beneficiary_enquiry_response,
		}[method](data, res)

	def _format_payment_response(self, data, res):
		accepted = data.get("StatusCode") == POSTING_ACCEPTED_CODE
		res.payment_status = "ACCEPTED" if accepted else "FAILED"
		res.message = data.get("StatusDesc", "")
		res.batch_ref_no = data.get("BatchRefNo", "")
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

	def _format_beneficiary_request_response(self, data, res):
		accepted = data.get("StatusCode") == POSTING_ACCEPTED_CODE
		res.status = "Accepted" if accepted else "Failed"
		res.message = data.get("StatusDesc", "")

	def _format_beneficiary_enquiry_response(self, data, res):
		beneficiaries = data.get("BeneResp", {}).get("BeneList", [])
		res.status = "Fetched" if beneficiaries else "Request Failure"
		res.beneficiaries = {
			bene.get("BenCode"): {
				"status": BENEFICIARY_STATUS.get(bene.get("StatusCode"), bene.get("StatusCode", "")),
				"message": bene.get("StatusDesc", ""),
			}
			for bene in beneficiaries
		}


# ---- Bank Account beneficiary registration ----
# Surfaces add_beneficiaries/get_beneficiary_status - which are IndusInd-only
# concepts (HDFC/ICICI take beneficiary details ad-hoc, per payment, with no
# registration step) - as actions on a supplier's Bank Account, since that's
# the natural place beneficiary details live.

ALL_TRAN_TYPES = "IMPS,NEFT,RTGS"


def get_default_indusind_connector():
	connectors = frappe.get_all("IndusInd Bank Connector", pluck="name")
	if not connectors:
		frappe.throw(_("No IndusInd Bank Connector is configured."))
	if len(connectors) > 1:
		frappe.throw(
			_("Multiple IndusInd Bank Connectors found - please specify which one to use.")
		)
	return connectors[0]


@frappe.whitelist()
def get_indusind_connectors():
	return frappe.get_all("IndusInd Bank Connector", pluck="name")


@frappe.whitelist()
def add_beneficiary_for_bank_account(bank_account, connector=None):
	ba = frappe.get_doc("Bank Account", bank_account)
	conn = frappe.get_doc(
		"IndusInd Bank Connector", connector or get_default_indusind_connector()
	)

	ben_code = ba.get("indusind_ben_code") or frappe.generate_hash(length=8).upper()
	batch_id = frappe.generate_hash(length=10)

	beneficiary = {
		"req_mode": "A",
		"ben_code": ben_code,
		"ben_name": ba.account_name,
		"ben_email": ba.email,
		"ben_mobile": ba.mobile_number,
	}
	# Two mutually exclusive shapes per the bank's own sample payloads
	# (test_beneficiary_request_matches_bank_sample_shape): a same-bank
	# beneficiary uses "IFTO" + IblAcctNo only; everyone else uses the rail
	# list + BenIFSC/BenAcctNo, with IblAcctNo left empty. Sending both
	# (as this used to) gets rejected with "Invalid IFT Transaction Type".
	if ba.bank == conn.bank:
		beneficiary["tran_type"] = "IFTO"
		beneficiary["ibl_acct_no"] = ba.bank_account_no
	else:
		beneficiary["tran_type"] = ALL_TRAN_TYPES
		beneficiary["ben_ifsc"] = ba.branch_code
		beneficiary["ben_acct_no"] = ba.bank_account_no

	res = conn.add_beneficiaries([beneficiary], batch_id=batch_id)

	frappe.db.set_value(
		"Bank Account",
		bank_account,
		{
			"indusind_ben_code": ben_code,
			"indusind_beneficiary_batch_id": batch_id,
			"indusind_beneficiary_status": "Pending" if res.status == "Accepted" else "Rejected",
			"indusind_beneficiary_message": res.message or "",
		},
	)
	return res


@frappe.whitelist()
def check_beneficiary_status_for_bank_account(bank_account, connector=None):
	ba = frappe.get_doc("Bank Account", bank_account)
	batch_id = ba.get("indusind_beneficiary_batch_id")
	if not batch_id:
		frappe.throw(_("This Bank Account has not been registered as a beneficiary yet."))

	conn = frappe.get_doc(
		"IndusInd Bank Connector", connector or get_default_indusind_connector()
	)
	res = conn.get_beneficiary_status(ref_no=batch_id)

	details = frappe._dict((res.beneficiaries or {}).get(ba.indusind_ben_code, {}))
	frappe.db.set_value(
		"Bank Account",
		bank_account,
		{
			"indusind_beneficiary_status": details.get("status") or "Pending",
			"indusind_beneficiary_message": details.get("message", ""),
		},
	)
	return res
