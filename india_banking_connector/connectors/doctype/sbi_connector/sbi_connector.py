# Copyright (c) 2026, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

import base64
import hashlib
import json
import secrets
import string
from collections import OrderedDict
from datetime import datetime

import frappe
import requests
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA1, SHA256
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate
from frappe.utils import cstr, flt, getdate

from india_banking_connector.connectors.bank_connector import BankConnector
from india_banking_connector.india_banking_connector.doctype.bank_request_log.bank_request_log import (
	create_api_log,
)


class SBIConnector(BankConnector):
	bank = "State Bank of India"

	__all__ = [
		"initiate_payment",
		"get_payment_status",
		"get_bank_balance",
		"get_bank_statement",
	]

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		self.bulk_transaction = kwargs.get("bulk_transaction")
		self.doc = frappe._dict(kwargs.get("doc", {}))
		self.payment_doc = frappe._dict(kwargs.get("payment_doc", {}))
		self.account_config = {}
		self._last_aes_key = None

	@property
	def headers(self):
		if not self._last_aes_key:
			self._last_aes_key = self.generate_aes_key()
		return {
			"Content-Type": "application/json",
			"AccessToken": self.rsa_oaep_encrypt(
				self._last_aes_key,
				self.load_public_key_from_cert(self.eis_encryption_cert),
			),
		}

	def initiate_payment(self):
		self._last_aes_key = None
		payment_details = self.payment_doc if not self.bulk_transaction else self.doc
		unique_id = self.get_unique_request_id(payment_details)

		if existing_payment_response := self.validate_duplicate_payments(
			unique_id=unique_id
		):
			return existing_payment_response

		url = self.urls.make_payment
		headers = self.headers
		payload = self.get_encrypted_payload(method="make_payment")
		response = requests.post(
			url,
			headers=headers,
			json=payload,
			verify=self.get_ssl_verify(),
			timeout=120,
		)

		log_id = create_api_log(
			response,
			action="Initiate Payment",
			account_config=self.account_config,
			ref_doctype=payment_details.parenttype or payment_details.doctype,
			ref_docname=payment_details.parent or payment_details.name,
			unique_id=unique_id,
			connector=self,
		)

		return self.get_decrypted_response(
			response, method="make_payment", log_id=log_id
		)

	def get_payment_status(self):
		self._last_aes_key = None
		payment_details = self.payment_doc if not self.bulk_transaction else self.doc
		unique_id = self.get_unique_request_id(payment_details)

		url = self.urls.payment_status
		headers = self.headers
		payload = self.get_encrypted_payload(method="payment_status")
		response = requests.post(
			url,
			headers=headers,
			json=payload,
			verify=self.get_ssl_verify(),
			timeout=120,
		)

		log_id = create_api_log(
			response,
			action="Payment Status",
			account_config=self.account_config,
			ref_doctype=payment_details.parenttype or payment_details.doctype,
			ref_docname=payment_details.parent or payment_details.name,
			unique_id=unique_id,
			connector=self,
		)

		return self.get_decrypted_response(
			response, method="payment_status", log_id=log_id
		)

	def get_bank_balance(self):
		if not self.balance_check:
			frappe.throw("Bank Balance Check is not enabled.")

		self._last_aes_key = None
		url = self.urls.bank_balance
		headers = self.headers
		payload = self.get_encrypted_payload(method="bank_balance")
		response = requests.post(
			url,
			headers=headers,
			json=payload,
			verify=self.get_ssl_verify(),
			timeout=120,
		)

		log_id = create_api_log(
			response,
			action="Bank Balance",
			account_config=self.account_config,
			ref_doctype=self.doctype,
			ref_docname=self.name,
			unique_id=self.account_number,
			connector=self,
		)

		return self.get_decrypted_response(
			response, method="bank_balance", log_id=log_id
		)

	def get_bank_statement(self):
		if not self.statement_fetch:
			frappe.throw("Bank Statement Fetch is not enabled.")

		self._last_aes_key = None
		url = self.urls.bank_statement
		headers = self.headers
		payload = self.get_encrypted_payload(method="bank_statement")
		response = requests.post(
			url,
			headers=headers,
			json=payload,
			verify=self.get_ssl_verify(),
			timeout=120,
		)

		log_id = create_api_log(
			response,
			action="Bank Statement",
			account_config=self.account_config,
			ref_doctype=self.doctype,
			ref_docname=self.name,
			unique_id=self.account_number,
			connector=self,
		)

		return self.get_decrypted_response(
			response, method="bank_statement", log_id=log_id
		)

	def get_encrypted_payload(self, method):
		if not self._last_aes_key:
			self._last_aes_key = self.generate_aes_key()
		plain_payload = self.get_account_config(method)
		plain_json = self.compact_json(plain_payload)

		request_reference_number = plain_payload["REQUEST_REFERENCE_NUMBER"]
		return {
			"REQUEST_REFERENCE_NUMBER": request_reference_number,
			"REQUEST": self.aes_gcm_encrypt(plain_json, self._last_aes_key),
			"DIGI_SIGN": self.digital_sign(plain_json),
		}

	def get_decrypted_response(self, response, method, log_id=None):
		res_dict = frappe._dict({})
		if not response.ok:
			res_dict.status = "Request Failure"
			res_dict.error = response.text
			return res_dict

		response_json = response.json()
		decrypted_response = self.process_response(response_json)
		self.set_decrypted_response(log_id, decrypted_response)
		self.get_formated_response(decrypted_response, res_dict, method)
		return res_dict

	def process_response(self, response_json):
		encrypted_response = response_json.get("RESPONSE")
		digi_sign = response_json.get("DIGI_SIGN")

		if not encrypted_response:
			return response_json

		decrypted_json = self.aes_gcm_decrypt(encrypted_response, self._last_aes_key)

		if digi_sign:
			self.verify_digital_sign(
				decrypted_json,
				digi_sign,
				self.load_public_key_from_cert(self.eis_encryption_cert),
			)

		decrypted = json.loads(decrypted_json)
		result = {
			"REQUEST_REFERENCE_NUMBER": response_json.get(
				"REQUEST_REFERENCE_NUMBER"
			),
			"RESPONSE_DATE": response_json.get("RESPONSE_DATE"),
			"RESPONSE_STATUS": decrypted.get("RESPONSE_STATUS"),
			"ERROR_CODE": decrypted.get("ERROR_CODE"),
			"ERROR_DESCRIPTION": decrypted.get("ERROR_DESCRIPTION"),
			"EIS_RESPONSE": self.parse_json(decrypted.get("EIS_RESPONSE")),
		}
		return result

	def get_formated_response(self, data, res_dict, method):
		data = self.parse_json(data)

		if data.get("RESPONSE_STATUS") and cstr(data.get("RESPONSE_STATUS")) != "0":
			message = (
				data.get("ERROR_DESCRIPTION")
				or data.get("ERROR_CODE")
				or "SBI request failed"
			)
			if method in ("bank_balance", "bank_statement"):
				res_dict.server_status = "Failed"
				res_dict.message = message
			else:
				res_dict.payment_status = "FAILED"
				res_dict.message = message
			return

		eis_response = self.parse_json(data.get("EIS_RESPONSE")) or {}
		if method == "make_payment":
			self.format_payment_response(eis_response, res_dict)
		elif method == "payment_status":
			self.format_status_response(eis_response, res_dict)
		elif method == "bank_balance":
			self.format_balance_response(eis_response, res_dict)
		elif method == "bank_statement":
			self.format_statement_response(eis_response, res_dict)

	def format_payment_response(self, eis_response, res_dict):
		response = frappe._dict(eis_response.get("TransactionCreationResponse") or {})
		response_code = cstr(response.get("responseCode"))
		response_message = response.get("responseMessage") or ""
		summary_name = self.get_payment_summary_name()

		if response_code in ("00", "0") or cstr(response_message).upper() in (
			"ACCEPTED",
			"SUCCESS",
		):
			res_dict.payment_status = "ACCEPTED"
			res_dict.message = response_message or "Payment Accepted"
			res_dict.file_sequence_number = response.get("batchNo")
			res_dict.summary_details = {
				summary_name: {
					"payment_status": "Accepted",
					"message": response_message,
					"batch_no": response.get("batchNo"),
				}
			}
		else:
			res_dict.payment_status = "FAILED"
			res_dict.message = response_message or "Payment Failed"

	def format_status_response(self, eis_response, res_dict):
		response = frappe._dict(eis_response.get("TransactionEnquiryResponse") or {})
		summary_name = self.get_payment_summary_name()
		corporate_ref_no = self.get_corporate_ref_no()
		transaction_details = response.get("transactionEnquiryDetails") or []
		if isinstance(transaction_details, dict):
			transaction_details = [transaction_details]

		status_details = frappe._dict({})
		for transaction in transaction_details:
			transaction = frappe._dict(transaction)
			ref_no = transaction.get("transactionRefNo") or transaction.get(
				"corporateRefNo"
			)
			if ref_no and ref_no != corporate_ref_no:
				continue

			status, message = self.get_payment_status_from_sbi(
				transaction.get("status"),
				transaction.get("statusDesc") or transaction.get("errorMessage"),
			)
			status_details = frappe._dict(
				{
					"status": status,
					"utr_number": transaction.get("utrNo")
					or transaction.get("utrNumber"),
					"message": message,
					"processed_date": transaction.get("valueDate")
					or transaction.get("processedDate"),
				}
			)
			break

		if not status_details:
			status, message = self.get_payment_status_from_sbi(
				response.get("batchStatus"), response.get("responseMessage")
			)
			status_details = frappe._dict(
				{
					"status": status,
					"utr_number": "",
					"message": message or "SBI transaction status not available",
				}
			)

		res_dict.payment_status = "PROCESSED"
		res_dict.summary_details = {summary_name: status_details}

	def format_balance_response(self, eis_response, res_dict):
		eis_response = frappe._dict(self.parse_json(eis_response) or {})

		if cstr(eis_response.get("responseStatus") or "0") != "0":
			res_dict.server_status = "Failed"
			res_dict.message = (
				eis_response.get("errorDescription")
				or eis_response.get("errorCode")
				or "Balance fetch failed"
			)
			return

		res_dict.server_status = "Success"
		res_dict.balance = self.parse_signed_amount(
			eis_response.get("availableAmount")
			or eis_response.get("availableBalance")
		)
		res_dict.date = eis_response.get("responseDate") or getdate()

	def format_statement_response(self, eis_response, res_dict):
		eis_response = frappe._dict(self.parse_json(eis_response) or {})

		if cstr(eis_response.get("responseStatus") or "0") != "0":
			res_dict.server_status = "Failed"
			res_dict.message = (
				eis_response.get("errorDescription")
				or eis_response.get("errorCode")
				or "Statement fetch failed"
			)
			return

		details = eis_response.get("accountStatementDetails") or []
		if isinstance(details, dict):
			details = [details]

		transactions = []
		for txn in details:
			txn = frappe._dict(txn)
			transactions.append(
				{
					"transaction_date": self.parse_statement_date(
						txn.get("VALUE_DATE") or txn.get("TODAYS_DATE")
					),
					"transaction_amount": self.parse_signed_amount(txn.get("AMOUNT")),
					"reference_number": (
						txn.get("STATEMENT")
						or txn.get("RECORD_NUMBER")
						or txn.get("CHEQUE_NUMBER")
					),
					"user_ref_number": cstr(txn.get("RECORD_NUMBER") or ""),
					"transaction_description": (
						txn.get("NARRATION")
						or txn.get("TRANSFER_STATEMENT")
						or txn.get("MISC_NARRATION")
						or ""
					),
				}
			)

		res_dict.server_status = "Success"
		res_dict.bank_statements = transactions

	def parse_signed_amount(self, value):
		"""SBI denotes sign with a leading (balance) or trailing (statement)
		'+'/'-'. Returns a float where debits are negative."""
		text = cstr(value).strip()
		if not text:
			return 0

		sign = -1 if (text.startswith("-") or text.endswith("-")) else 1
		return sign * flt(text.strip("+-").strip())

	def parse_statement_date(self, value):
		"""SBI statement dates are in DD/MM/YYYY format."""
		text = cstr(value).strip()
		if not text:
			return ""
		try:
			return datetime.strptime(text, "%d/%m/%Y").date()
		except ValueError:
			return getdate(text)

	def get_statement_date(self, value):
		"""Convert the incoming date into SBI's DDMMYYYY format.

		The Bank Statements dialog sends ISO (yyyy-mm-dd) dates, while the
		india_banking default fallback sends day-first (dd-mm-yyyy) dates.
		ISO is unambiguous, so only dd-mm-yyyy needs day-first parsing -
		otherwise getdate would silently swap the day and month."""
		if value is None:
			frappe.throw("Statement from/to date is required.")

		if not isinstance(value, str):
			return getdate(value).strftime("%d%m%Y")

		text = value.strip()
		if not text:
			frappe.throw("Statement from/to date is required.")

		iso_like = len(text.split("-", 1)[0]) == 4  # leading yyyy of yyyy-mm-dd
		return getdate(text, parse_day_first=not iso_like).strftime("%d%m%Y")

	def get_account_config(self, method):
		request_reference_number = self.generate_request_reference_number()
		if method == "make_payment":
			inner_request = {
				"uniqueRequestId": self.get_unique_request_id(
					self.payment_doc, method
				),
				"corporateCode": self.corporate_code,
				"corporateProductCode": self.corporate_product_code,
				"transactionDetails": [self.get_transaction()],
			}
			plain_payload = {
				"REQUEST_REFERENCE_NUMBER": request_reference_number,
				"SOURCE_ID": self.source_id,
				"DESTINATION": "CMP",
				"TXN_TYPE": "PAYMENT",
				"TXN_SUB_TYPE": "POSTING",
				"EIS_PAYLOAD": {
					"TransactionCreationRequest": inner_request,
					"HASH": self.compute_hash(inner_request),
				},
			}
		elif method == "payment_status":
			inner_request = {
				"uniqueRequestId": self.get_unique_request_id(
					self.payment_doc, method
				),
				"corporateCode": self.corporate_code,
				"transactionRequestId": self.get_unique_request_id(
					self.payment_doc, "make_payment"
				),
				"transactionRefNo": self.get_corporate_ref_no(),
			}
			plain_payload = {
				"REQUEST_REFERENCE_NUMBER": request_reference_number,
				"SOURCE_ID": self.source_id,
				"DESTINATION": "CMP",
				"TXN_TYPE": "PAYMENT",
				"TXN_SUB_TYPE": "ENQUIRY",
				"EIS_PAYLOAD": {
					"TransactionEnquiryRequest": inner_request,
					"HASH": self.compute_hash(inner_request),
				},
			}
		elif method == "bank_balance":
			inner_request = {
				"accountNo": self.account_number,
				"corporateCode": self.corporate_code,
			}
			plain_payload = {
				"REQUEST_REFERENCE_NUMBER": request_reference_number,
				"SOURCE_ID": self.source_id,
				"DESTINATION": "CMP",
				"TXN_TYPE": "ACCOUNT",
				"TXN_SUB_TYPE": "BALANCE",
				"EIS_PAYLOAD": {
					"AccountBalanceRequest": inner_request,
					"HASH": self.compute_hash(inner_request),
				},
			}
		elif method == "bank_statement":
			inner_request = {
				"accountNo": self.account_number,
				"corporateCode": self.corporate_code,
				"fromDate": self.get_statement_date(self.doc.get("from_date")),
				"toDate": self.get_statement_date(self.doc.get("to_date")),
			}
			plain_payload = {
				"REQUEST_REFERENCE_NUMBER": request_reference_number,
				"SOURCE_ID": self.source_id,
				"DESTINATION": "CMP",
				"TXN_TYPE": "ACCOUNT",
				"TXN_SUB_TYPE": "STATEMENT",
				"EIS_PAYLOAD": {
					"AccountStatementRequest": inner_request,
					"HASH": self.compute_hash(inner_request),
				},
			}
		else:
			frappe.throw(f"Unsupported SBI method {method}")

		self.account_config = plain_payload
		return plain_payload

	def get_transaction(self):
		payment_details = self.payment_doc
		return {
			"bicCode": payment_details.branch_code or "",
			"beneAddress1": "",
			"beneAddress2": "",
			"beneAddress3": "",
			"remittanceCode": "",
			"debitAccountNumber": self.account_number,
			"corporateRefNo": self.get_corporate_ref_no(),
			"paymentAmount": cstr(flt(payment_details.amount, 2)),
			"chargeBournedBy": "",
			"paymentInstruction1": self.get_payment_instruction(),
			"paymentInstruction2": "",
			"paymentInstruction3": "",
			"paymentInstruction4": "",
			"remarks": payment_details.get("party") or "",
			"paymentMethodName": self.get_payment_method(
				payment_details.mode_of_transfer
			),
			"payableCurrency": "INR",
			"beneAccNo": self.clean_string(payment_details.bank_account_no),
			"beneCode": "",
			"beneName": (
				payment_details.party_name or payment_details.party or ""
			)[:100],
			"bankSortCode": "",
			"intermediaryBankBICCode": "",
			"executionDate": getdate().strftime("%d-%b-%Y").upper(),
		}

	def get_payment_instruction(self):
		payment_details = self.payment_doc
		reference_name = payment_details.get("reference_name")
		if reference_name:
			return self.clean_sbi_text(reference_name, max_length=35)

		for reference in self.doc.get("references") or []:
			reference = frappe._dict(reference)
			if reference.name in cstr(payment_details.get("summary_references")):
				return self.clean_sbi_text(
					reference.reference_name or reference.name, max_length=35
				)

		return self.clean_sbi_text(
			payment_details.get("parent") or payment_details.name, max_length=35
		)

	def clean_sbi_text(self, value, max_length=None):
		text = "".join(char for char in cstr(value) if char.isalnum() or char.isspace())
		text = " ".join(text.split())
		return text[:max_length] if max_length else text


	def get_payment_method(self, mode_of_transfer):
		mode = cstr(mode_of_transfer).upper()
		if "RTGS" in mode:
			return "RTGS"
		if "NEFT" in mode:
			return "NEFT"
		if "A2A" in mode or "INTRA" in mode or "DCR" in mode:
			return "DCR"
		return mode
	

	def get_unique_request_id(self, payment_details, method=None):
		unique_id = self.get_numeric_hash(payment_details.get("name"), length=11)
		if method == "payment_status":
			return self.get_numeric_hash(f"{unique_id}-ENQ", length=11)
		return unique_id

	def get_payment_summary_name(self):
		return self.payment_doc.name

	def get_corporate_ref_no(self):
		return "SBI" + self.get_alphanumeric_hash(self.get_payment_summary_name(), 13)

	def get_numeric_hash(self, value, length):
		hash_int = int(hashlib.sha256(cstr(value).encode("utf-8")).hexdigest(), 16)
		return str(hash_int % (10**length)).zfill(length)

	def get_alphanumeric_hash(self, value, length):
		return hashlib.sha256(cstr(value).encode("utf-8")).hexdigest()[:length].upper()

	def get_payment_status_from_sbi(self, status, message=None):
		status = cstr(status).upper()
		message = message or status or "Status not available"
		if status in (
			"PROCESSED",
			"SUCCESS",
			"PARTIALLY SUCCESSFUL",
			"PARTIALLY SUCESSFUL",
		):
			return "Processed", message
		if status in ("REJECTED", "CANCEL REJECTED", "CANCELLED", "CANCELED"):
			return "Rejected", message
		if status in (
			"FAILED",
			"RETURNED",
			"NO SUCH TRANSACTION DETAIL FOUND",
			"INVALID TRANSACTION DETAILS",
		):
			return "Failed", message
		if status in (
			"ACCEPTED",
			"OPEN",
			"PROCESSING",
			"PROCESSING ERROR",
			"SENT TO BENEFICIARY BANK",
			"TO BE FUNDED",
			"NOT YET AUTHORISED",
			"UNAUTHORIZED",
			"PENDING FOR RELEASE",
			"INTERNAL SERVER ERROR",
			"OPERATION COULD NOT BE PROCESSED",
		):
			return "Pending", message
		return "Pending", message

	def compute_hash(self, inner_request):
		return self.digital_sign(self.compact_json(self.sort_json_keys(inner_request)))

	def digital_sign(self, data):
		signature = self.load_client_private_key().sign(
			data.encode("utf-8"),
			asym_padding.PKCS1v15(),
			SHA256(),
		)
		return base64.b64encode(signature).decode("ascii")

	def verify_digital_sign(self, data, signature, public_key):
		public_key.verify(
			base64.b64decode(signature),
			data.encode("utf-8"),
			asym_padding.PKCS1v15(),
			SHA256(),
		)

	def rsa_oaep_encrypt(self, data, public_key):
		encrypted = public_key.encrypt(
			data,
			asym_padding.OAEP(
				mgf=asym_padding.MGF1(algorithm=SHA1()),
				algorithm=SHA1(),
				label=None,
			),
		)
		return base64.b64encode(encrypted).decode("ascii")

	def aes_gcm_encrypt(self, plaintext, key):
		aesgcm = AESGCM(key)
		encrypted = aesgcm.encrypt(key[:12], plaintext.encode("utf-8"), None)
		return base64.b64encode(encrypted).decode("ascii")

	def aes_gcm_decrypt(self, ciphertext, key):
		aesgcm = AESGCM(key)
		decrypted = aesgcm.decrypt(key[:12], base64.b64decode(ciphertext), None)
		return decrypted.decode("utf-8")

	def generate_aes_key(self):
		alphabet = string.ascii_letters + string.digits
		return "".join(secrets.choice(alphabet) for _ in range(32)).encode("ascii")

	def generate_request_reference_number(self):
		source_id = cstr(self.source_id)
		now = datetime.now()
		timestamp = (
			now.strftime("%y")
			+ f"{now.timetuple().tm_yday:03d}"
			+ now.strftime("%H%M%S")
			+ f"{now.microsecond // 1000:03d}"
		)

		if len(source_id) == 5:
			sequence = self.get_digit_sequence(3)
		else:
			sequence = self.get_digit_sequence(6)

		request_reference_number = f"SBI{source_id}{timestamp}{sequence}"
		if len(request_reference_number) != 25:
			frappe.throw(
				"Invalid SBI Source ID. Request reference number must be 25 characters."
			)
		return request_reference_number

	def get_digit_sequence(self, length):
		return "".join(secrets.choice(string.digits) for _ in range(length))

	def sort_json_keys(self, obj):
		if isinstance(obj, dict):
			return OrderedDict(
				sorted(
					((key, self.sort_json_keys(value)) for key, value in obj.items()),
					key=lambda item: item[0],
				)
			)
		if isinstance(obj, list):
			return [self.sort_json_keys(item) for item in obj]
		return obj

	def compact_json(self, obj):
		return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)

	def parse_json(self, value):
		if isinstance(value, str) and value.strip():
			try:
				return json.loads(value)
			except json.JSONDecodeError:
				return value
		return value

	def load_client_private_key(self):
		password = self.get_password(
			"client_private_key_password", raise_exception=False
		)
		password = password.encode("utf-8") if password else None
		with open(self.get_file_relative_path(self.client_private_key), "rb") as file:
			return load_pem_private_key(file.read(), password=password)

	def load_public_key_from_cert(self, file_url):
		with open(self.get_file_relative_path(file_url), "rb") as file:
			cert = load_pem_x509_certificate(file.read())
		return cert.public_key()

	def get_ssl_verify(self):
		if self.ssl_verify_cert:
			return self.get_file_relative_path(self.ssl_verify_cert)
		return True
