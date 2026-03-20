# Copyright (c) 2026, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

import copy
import json
import re
from base64 import b64encode

import frappe
import requests
from frappe import _
from frappe.utils import cstr, flt, get_datetime, getdate
from jose.constants import ALGORITHMS

from india_banking_connector.connectors.bank_connector import BankConnector
from india_banking_connector.india_banking_connector.doctype.bank_request_log.bank_request_log import (
	create_api_log,
)


class CanaraBankConnector(BankConnector):
	bank = "Canara Bank"

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		self.bulk_transaction = kwargs.get("bulk_transaction")
		self.doc = frappe._dict(kwargs.get("doc", {}))
		self.payment_doc = frappe._dict(kwargs.get("payment_doc", {}))

		self.account_config = {}

	@property
	def urls(self):
		self.update_aes_key()
		return super().urls

	@property
	def headers(self):
		cert = self.get_file_content(self.cert)
		cert_key = (
			cert.lstrip("-----BEGIN CERTIFICATE-----")
			.rstrip("-----END CERTIFICATE-----")
			.strip()
		).replace("\n", "")  # normalise

		return {
			"x-client-id": self.get_password("client_id"),
			"x-client-secret": self.get_password("client_secret"),
			"x-client-certificate": cert_key,
			"x-api-interaction-id": "1",
			"x-timestamp": cstr(int(get_datetime().timestamp() * 1000)),
			"x-signature": "",
			"Content-Type": "application/json",
		}

	def get_auth(self):
		login_id = self.login_id
		login_password = self.login_password
		if self.enable_password_encryption:
			login_password = self.encrypted_login_password

		auth_string = login_id + ":" + login_password
		return b64encode(auth_string.encode()).decode()

	def update_aes_key(self):
		if self.aes_key:
			self.AES_KEY = bytes.fromhex(self.get_password("aes_key"))

	def get_cert(self):
		return None

	def initiate_payment(self):
		payment_details = self.doc
		unique_id = "".join(re.findall(r"[0-9a-zA-Z]", payment_details.name))

		if existing_payment_response := self.validate_duplicate_payments(
			unique_id=unique_id,
		):
			return existing_payment_response

		url = self.urls.make_payment
		headers = self.headers

		signature, payload = self.get_encrypted_payload(method="make_payment")
		headers["x-signature"] = signature

		response = requests.post(
			url, headers=headers, json=payload, cert=self.get_cert()
		)

		log_id = create_api_log(
			response,
			action="Initiate Payment",
			account_config=self.account_config,
			ref_doctype=payment_details.doctype,
			ref_docname=payment_details.name,
			unique_id=unique_id,
			connector=self,
		)

		return self.get_decrypted_response(
			response, method="make_payment", log_id=log_id
		)

	def get_payment_status(self):
		payment_details = self.doc
		unique_id = "".join(re.findall(r"[0-9a-zA-Z]", payment_details.name))

		url = self.urls.payment_status
		headers = self.headers

		signature, payload = self.get_encrypted_payload(method="payment_status")
		headers["x-signature"] = signature

		response = requests.post(
			url, headers=headers, json=payload, cert=self.get_cert()
		)

		log_id = create_api_log(
			response,
			action="Payment Status",
			account_config=self.account_config,
			ref_doctype=payment_details.doctype,
			ref_docname=payment_details.name,
			unique_id=unique_id,
			connector=self,
		)

		return self.get_decrypted_response(
			response, method="payment_status", log_id=log_id
		)

	def get_bank_balance(self):
		if not self.balance_check:
			frappe.throw(_("Bank Balance is disabled."))

		url = self.urls.bank_balance
		headers = self.headers

		signature, payload = self.get_encrypted_payload(method="bank_balance")
		headers["x-signature"] = signature

		response = requests.post(
			url, headers=headers, json=payload, cert=self.get_cert()
		)

		log_id = create_api_log(
			response,
			action="Bank Balance",
			account_config=self.account_config,
			ref_doctype=self.doctype,
			ref_docname=self.name,
			unique_id=self.name,
			connector=self,
		)

		return self.get_decrypted_response(
			response, method="bank_balance", log_id=log_id
		)

	def get_bank_statement(self):
		if not self.statement_fetch:
			frappe.throw(_("Statement fetch is disabled."))

		url = self.urls.bank_statement
		headers = self.headers

		signature, payload = self.get_encrypted_payload(method="bank_statement")
		headers["x-signature"] = signature

		response = requests.post(
			url, headers=headers, json=payload, cert=self.get_cert()
		)

		log_id = create_api_log(
			response,
			action="Bank Statement",
			account_config=self.account_config,
			ref_doctype=self.doctype,
			ref_docname=self.name,
			unique_id=self.name,
			connector=self,
		)

		return self.get_decrypted_response(
			response, method="bank_statement", log_id=log_id
		)

	def get_encrypted_payload(self, method):
		self.update_account_config(method)
		encrypted = self.jwe_encrypt(
			json.dumps(
				self.account_config["Request"]["body"]["encryptData"],
				separators=(",", ":"),
			),
			self.AES_KEY,
			media_type=None,
			encryption=ALGORITHMS.A128CBC_HS256,
			algorithm=ALGORITHMS.A256KW,
		)

		payload = copy.deepcopy(self.account_config)
		payload["Request"]["body"]["encryptData"] = encrypted.decode("utf-8")

		return (
			self.generate_signature(
				json.dumps(self.account_config, separators=(",", ":")),
				self.get_file_content(self.private_key),
			),
			payload,
		)

	def get_decrypted_response(self, response, method: str, log_id: str):
		self.update_aes_key()
		res_dict = frappe._dict({})
		if response.ok or "encryptData" in response.text:
			decrypted_data = frappe._dict({})
			try:
				response = json.loads(response.text)
				encrypted_data = (
					response.get("Response", {}).get("body", {}).get("encryptData", "")
				)
				if not encrypted_data:
					res_dict.status = "FAILED"
					res_dict.message = "Data Not Found!"

				decrypted_data = self.jwe_decrypt(
					encrypted_data,
					self.AES_KEY,
				).decode("utf-8")
				self.set_decrypted_response(log_id, decrypted_data)
			except Exception:
				frappe.log_error(
					"Decryption Failed", frappe.get_traceback(with_context=1)
				)
				res_dict.status = "FAILED"
				res_dict.message = "Response Decryption Failed!"
				return res_dict

			self.get_formated_response(decrypted_data, res_dict, method)
		else:
			res_dict.status = "Request Failure"
			res_dict.message = response.text or response.status_code

		return res_dict

	def update_account_config(self, method):
		method_map = {
			"make_payment": self.set_payment_data,
			"payment_status": self.set_payment_status_data,
			"bank_balance": self.set_balance_data,
			"bank_statement": self.set_statement_data,
		}

		if method in method_map:
			method_map[method]()

	def set_payment_data(self):
		payment_details = self.doc
		transaction_id = "".join(re.findall(r"[0-9a-zA-Z]", payment_details.name))

		tfa_password = self.get_password("tfa_password")
		key = ""
		if self.enable_password_encryption:
			tfa_password = self.get_password("encrypted_tfa_password")
			key = self.get_password("encryption_key")

		self.account_config.update(
			{
				"Request": {
					"body": {
						"encryptData": {
							"Authorization": "Basic " + self.get_auth(),
							"TFAPassword": tfa_password,
							"Key": key,
							"CustomerID": self.customer_id,
							"TotAmt": cstr(flt(payment_details.total, 2)),
							"TxnCnt": cstr(len(payment_details.get("summary"))),
							"DatTxn": getdate().strftime("%Y%m%d"),
							"BatchRequestID": transaction_id,
							"TxnDtls": {
								"Txn": self.get_transactions(),
							},
						}
					}
				}
			}
		)

	def get_transactions(self):
		def _get_party_name(summary):
			return self.clean_string(summary.get("party_name") or summary.get("party"))

		return [
			{
				"TxnRefNo": summary.get("name"),
				"DrAcct": summary.get("bank_account_no"),
				"SndrNm": self.clean_string(self.account_name),
				"TxnAmt": cstr(flt(summary.get("amount"), 2)),
				"TxnType": self.get_payment_mode(summary.get("mode_of_transfer")),
				"BenefIFSC": summary.get("branch_code"),
				"BenefAcNo": summary.get("bank_account_no"),
				"BenefAcNm": _get_party_name(summary),
				"Nrtv": f'Payment from {summary.get("parent", "")} for {_get_party_name(summary)}',
			}
			for summary in self.doc.get("summary")
		]

	def get_payment_mode(self, mode_of_transfer: str) -> str:
		mode_of_transfer = mode_of_transfer.lower()
		payment_mode = None
		if "a2a" in mode_of_transfer:
			payment_mode = "INTRA"
		elif "imps" in mode_of_transfer:
			payment_mode = "IMPS"
		elif "neft" in mode_of_transfer:
			payment_mode = "NEFT"
		elif "rtgs" in mode_of_transfer:
			payment_mode = "RTGS"

		return payment_mode

	def set_payment_status_data(self):
		payment_details = self.doc
		unique_id = "".join(re.findall(r"[0-9a-zA-Z]", payment_details.name))

		key = ""
		tfa_password = self.get_password("tfa_password")
		if self.enable_password_encryption:
			key = self.get_password("encryption_key")
			tfa_password = self.get_password("encrypted_tfa_password")

		self.account_config.update(
			{
				"Request": {
					"body": {
						"encryptData": {
							"Authorization": "Basic " + self.get_auth(),
							"TFAPassword": tfa_password,
							"Key": key,
							"CustomerID": self.customer_id,
							"BatchRequestID": unique_id,
							"TxnRefNo": "",
						}
					}
				}
			}
		)

	def set_balance_data(self):
		key = ""
		if self.enable_password_encryption:
			key = self.get_password("encryption_key")

		self.account_config.update(
			{
				"Request": {
					"body": {
						"branchCode": self.branch_code,
						"encryptData": {
							"Authorization": "Basic " + self.get_auth(),
							"acctNumber": self.account_number,
							"customerID": self.customer_id,
							"key": key,
						},
					}
				}
			}
		)

	def set_statement_data(self):
		payload_details = self.doc

		from_date = getdate(payload_details.get("from_date", "")).strftime("%d-%m-%Y")
		to_date = getdate(payload_details.get("to_date", "")).strftime("%d-%m-%Y")

		key = ""
		if self.enable_password_encryption:
			key = self.get_password("encryption_key")

		self.account_config.update(
			{
				"Request": {
					"body": {
						"encryptData": {
							"Authorization": "Basic " + self.get_auth(),
							"acctNumber": self.account_number,
							"customerID": self.customer_id,
							"NUMBEROFTXN": "",
							"FROMDATE": from_date,
							"TODATE": to_date,
							"searchBy": "3",
							"branchCode": self.branch_code,
							"key": key,
						}
					}
				}
			}
		)

	def get_formated_response(self, decrypted_data, res_dict, method):
		decrypted_data = json.loads(decrypted_data)
		if "ErrorResponse" in decrypted_data:
			message = (
				decrypted_data.get("ErrorResponse", {})
				.get("metadata", {})
				.get("status", {})
				.get("desc", "")
			)
			error_code = (
				decrypted_data.get("ErrorResponse", {})
				.get("metadata", {})
				.get("status", {})
				.get("code", "")
			)
			res_dict.status = "FAILED"
			res_dict.message = f"{message} - {error_code}"
			return

		method_map = {
			"make_payment": self.format_payment_response,
			"payment_status": self.format_payment_status_response,
			"bank_balance": self.format_bank_balance_response,
			"bank_statement": self.format_statement_response,
		}

		if method in method_map:
			method_map[method](decrypted_data, res_dict)

	def format_payment_response(self, decrypted_data, res_dict):
		if isinstance(decrypted_data, str):
			try:
				decrypted_data = json.loads(decrypted_data)
			except json.JSONDecodeError:
				try:
					decrypted_data = decrypted_data.replace("'", '"')
					decrypted_data = json.loads(decrypted_data)
				except json.JSONDecodeError:
					res_dict.status = "Failure"
					res_dict.message = "Failed to parse payment response."
					return

		status = decrypted_data.get("status", {})
		if status.get("result", "").lower() == "accepted":
			res_dict.payment_status = "ACCEPTED"
			res_dict.message = status.get("message", {}).get(
				"code", "Payments Initiated"
			)
			res_dict.summary_details = self.get_summary_details("Accepted")
		elif status.get("result", "").lower() == "accepted":
			res_dict.payment_status = "ACCEPTED"
			res_dict.message = status.get("message", {}).get(
				"code", "Payments Initiated"
			)
			res_dict.summary_details = self.get_summary_details("Accepted")
		else:
			summary = (
				decrypted_data.get("Response", {}).get("Body", {}).get("txnSummary", {})
			)
			error_code = summary.get("ErrorCode")
			error_desc = summary.get("ErrorDec")
			res_dict.status = "Request Failure"
			res_dict.message = error_desc or "Unexpected response format."
			res_dict.error_code = error_code

	def get_status(self, status_code):
		status = "Pending"
		if status_code == "Initiated":
			status = "Initiated"
		elif status_code == "Successful":
			status = "Processed"
		elif status_code == "Rejected":
			status = "Rejected"
		elif status_code == "Failed":
			status = "Failed"

		return status

	def format_payment_status_response(self, decrypted_data, res_dict):
		if isinstance(decrypted_data, str):
			try:
				decrypted_data = json.loads(decrypted_data)
			except json.JSONDecodeError:
				try:
					decrypted_data = decrypted_data.replace("'", '"')
					decrypted_data = json.loads(decrypted_data)
				except json.JSONDecodeError:
					res_dict.status = "Failure"
					res_dict.message = "Failed to parse payment response."
					return

		transactions = decrypted_data.get("TxnDtls", {}).get("Txn")

		if transactions:
			res_dict.payment_status = "PROCESSED"
			res_dict.message = "Payment status fetched successfully."
		else:
			res_dict.payment_status = "Request Failure"
			res_dict.message = "Invalid response format."

		summary_details = {}
		for transaction in transactions:
			transaction = frappe._dict(transaction)
			summary_details[transaction.crn] = {
				"unique_id": transaction.get("TxnRefNo", ""),
				"status_code": transaction.get("TxnStatus", ""),
				"status": self.get_status(transaction.get("TxnStatus", "")),
				"utr_number": transaction.get("utr_RRN_Number", ""),
				"message": transaction.get("TxnStatus", ""),
				"approved_date": transaction.get("Approved_Date"),
			}

		res_dict.summary_details = summary_details

		return res_dict

	def format_bank_balance_response(self, decrypted_data, res_dict):
		res_dict.server_status = "Success"
		res_dict.balance = decrypted_data.get("balAvailable", 0)
		res_dict.date = getdate()
		res_dict.current_balance = decrypted_data.get("currentBalance", 0)

	def format_statement_response(self, decrypted_data, res_dict):
		transactions = []

		for txn in decrypted_data.get("transactions", []):
			amount = abs(flt(txn.get("transactionAmount")))
			if txn.get("creditDebitFlag").lower() == "d":
				amount = -1 * amount
			transaction = {
				"transaction_date": txn.get("transactionDate", ""),
				"transaction_amount": amount,
				"reference_number": txn.get("txnRefNumber"),
				"user_ref_number": txn.get("userRefNumber", ""),
				"transaction_description": txn.get("description", ""),
			}
			transactions.append(transaction)

		res_dict.server_status = "Success"
		res_dict.bank_statements = transactions
