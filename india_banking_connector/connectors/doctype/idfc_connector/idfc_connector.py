# Copyright (c) 2025, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

import json
import random
import re

import frappe
import jwt
import requests
from frappe import _
from frappe.query_builder import DocType
from frappe.utils import add_to_date, get_datetime

from india_banking_connector.connectors.bank_connector import BankConnector
from india_banking_connector.india_banking_connector.doctype.bank_request_log.bank_request_log import (
	create_api_log,
)


class IDFCConnector(BankConnector):
	__all__ = [
		"initiate_payment",
		"get_payment_status",
	]

	LOW_ASCII_LIMIT = 47
	HIGH_ASCII_LIMIT = 126

	def __init__(self, *args, **kwargs):
		self.bank = "IDFC"
		super().__init__(*args, **kwargs)

		self.bulk_transaction = kwargs.get("bulk_transaction")
		self.doc = frappe._dict(kwargs.get("doc", {}))
		self.payment_doc = frappe._dict(kwargs.get("payment_doc", {}))

		self.account_config = {}

	@property
	def urls(self):
		self.update_aes_and_iv()
		if not self.bulk_transaction:
			frappe.throw("The scope has not been implemented.")
		CONNECTOR = DocType(self.doctype)
		EU = DocType("Endpoint URLs")
		urls = (
			frappe.qb.from_(CONNECTOR)
			.join(EU)
			.on(EU.parent == self.name)
			.select(EU.action, EU.url)
			.orderby(EU.idx)
		).run()

		return frappe._dict(dict(urls))

	def update_aes_and_iv(self):
		self.AES_KEY = bytes.fromhex(self.get_password("aes_key"))
		self.IV = self.generate_iv().encode()

	@property
	def headers(self):
		return {
			"source": self.corp_id,
			"correlationId": frappe.generate_hash(length=20),
			"Content-Type": "application/octet-stream",
			"Tran_Id": self.transaction_id,
			"corp_id": self.corp_id,
			"Authorization": "Bearer " + self.get_oauth_token(),
		}

	def generate_iv(self) -> str:
		iv_chars = [
			chr(random.randint(self.LOW_ASCII_LIMIT, self.HIGH_ASCII_LIMIT))
			for _ in range(16)
		]
		return "".join(iv_chars)

	@frappe.whitelist()
	def get_oauth_token(self):
		headers = {
			"Accept": "application/json",
			"Content-Type": "application/x-www-form-urlencoded",
		}

		data = {
			"grant_type": "client_credentials",
			"scope": self.scope,
			"client_id": self.get_password("client_id"),
			"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			"client_assertion": self.get_client_assertion(),
		}

		try:
			response = requests.post(
				self.urls.oauth_token,
				headers=headers,
				data=data,
			)

			create_api_log(
				response, action="Get OAuth Token", account_config=data, connector=self
			)

			if response.ok:
				return response.json().get("access_token")
		except Exception:
			frappe.log_error("Oauth Failed", frappe.get_traceback(with_context=True))
			frappe.throw(
				_(
					"Connection failed. Unable to authenticate with the connector. Please verify your credentials"
				)
			)

	def get_client_assertion(self):
		headers = {
			"alg": "RS256",
			"typ": "JWT",
			"kid": self.get_password("signing_key"),
		}
		payload = {
			"jti": frappe.generate_hash(length=30),
			"sub": self.get_password("client_id"),
			"iss": self.get_password("client_id"),
			"aud": self.urls.get("oauth_token"),
			"exp": int(
				add_to_date(get_datetime(), seconds=60).timestamp()
			),  # 60 seconds from current time
		}

		return jwt.encode(
			payload,
			self.get_file_content(self.private_key),
			algorithm="RS256",
			headers=headers,
		)

	def initiate_payment(self):
		payment_details = self.doc if self.bulk_transaction else self.payment_doc
		unique_id = "".join(re.findall(r"[0-9a-zA-Z]", payment_details.name))
		self.transaction_id = "NEFT" + unique_id

		if existing_payment_response := self.validate_duplicate_payments(
			unique_id=self.transaction_id,
		):
			return existing_payment_response

		url = self.urls.make_payment
		headers = self.headers
		payload = self.get_encrypted_payload(method="make_payment")

		response = requests.post(url, headers=headers, data=payload)

		log_id = create_api_log(
			response,
			action="Initiate Payment",
			account_config=self.account_config,
			ref_doctype=payment_details.doctype,
			ref_docname=payment_details.name,
			unique_id=self.transaction_id,
			connector=self,
		)

		return self.get_decrypted_response(
			response, method="make_payment", log_id=log_id
		)

	def get_payment_status(self):
		unique_id = "".join(re.findall(r"[0-9a-zA-Z]", self.doc.name))
		self.transaction_id = "NEFT" + unique_id

		url = self.urls.payment_status
		headers = self.headers
		payload = self.get_encrypted_payload(method="payment_status")

		response = requests.post(url, headers=headers, data=payload)

		log_id = create_api_log(
			response,
			action="Get Payment Status",
			account_config=self.account_config,
			ref_doctype=self.doc.doctype,
			ref_docname=self.doc.name,
			unique_id=self.transaction_id,
			connector=self,
		)

		return self.get_decrypted_response(
			response, method="payment_status", log_id=log_id
		)

	def get_encrypted_payload(self, method: str):
		self.update_account_config(method)
		return self.aes_encrypt_data(self.account_config, self.AES_KEY, prepend_iv=True)

	def get_decrypted_response(self, response, method: str, log_id: str):
		self.update_aes_and_iv()
		res_dict = frappe._dict({})
		if response.ok:
			decrypted_data = frappe._dict({})
			try:
				decrypted_data = self.aes_decrypt_data(
					response.text, self.AES_KEY, json_loads=True
				)
				self.set_decrypted_response(log_id, decrypted_data)
			except Exception:
				frappe.log_error(
					"Decryption Failed", frappe.get_traceback(with_context=1)
				)
				res_dict.status = "failed"
				res_dict.message = "Response Decryption Failed!"
				return res_dict

			self.get_formated_response(decrypted_data, res_dict, method)
		else:
			res_dict.status = "Request Failure"
			res_dict.message = response.text or response.status_code

		return res_dict

	def get_formated_response(self, decrypted_data, res_dict, method):
		method_map = {
			"make_payment": self.format_payment_response,
			"payment_status": self.format_payment_status_response,
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

		data = frappe._dict(decrypted_data)

		corp_res = data.get("doMultiPaymentCorpRes")

		if (
			corp_res
			and (header := corp_res.get("Header"))
			and header.get("Status") == "Success"
		):
			res_dict.payment_status = "ACCEPTED"
			res_dict.message = corp_res.get("Body", {}).get(
				"Remarks", "Payment initiated successfully."
			)
			res_dict.summary_details = self.get_summary_details("Accepted")
		elif (
			corp_res
			and (header := corp_res.get("Header"))
			and header.get("Status") == "Failed"
		):
			res_dict.payment_status = "ACCEPTED"
			err_msg = corp_res.get("Body", {}).get(
				"Remarks", "Payment initiated successfully."
			)
			res_dict.message = err_msg
			res_dict.summary_details = self.get_summary_details("Failed")
		else:
			res_dict.status = "Request Failure"
			res_dict.message = "Unexpected response format."

	def format_payment_status_response(self, decrypted_data, res_dict):
		if isinstance(decrypted_data, str):
			try:
				decrypted_data = json.loads(decrypted_data)
			except json.JSONDecodeError:
				try:
					decrypted_data = decrypted_data.replace("'", '"')
					decrypted_data = json.loads(decrypted_data)
				except json.JSONDecodeError:
					res_dict.status = "failed"
					res_dict.message = "Failed to parse payment status response."
					return

		data = frappe._dict(decrypted_data)

		corp_res = data.get("doMultiPaymentCorpRes")

		if (
			corp_res
			and (header := corp_res.get("Header"))
			and header.get("Status") == "Success"
			and (body := corp_res.get("Body"))
			and body.get("TranID_Status").lower() == "success"
		):
			res_dict.payment_status = "PROCESSED"
			res_dict.message = corp_res.get("Body", {}).get(
				"TranID_StatusDesc", "Payment status fetched successfully."
			)
			res_dict.summary_details = self.format_payment_status(
				corp_res.get("Body", {}).get("Transaction", [])
			)
		else:
			res_dict.status = "Request Failure"
			res_dict.message = "Unexpected response format."

	def format_payment_status(self, transactions):
		if isinstance(transactions, str):
			transactions = json.loads(transactions)

		result = {}
		for transaction in transactions:
			ref_no = transaction.get("RefNo")
			status = transaction.get("RefStatus", "")
			msg = transaction.get("StatusDesc", "") or transaction.get(
				"Status_Desc", ""
			)
			utr_no = ""
			if status == "SUCCESS":
				payment_status = "Processed"
				msg = msg or "Transaction completed successfully."
				utr_no = transaction.get("UTR_No", "")
			elif status in ["Pending Auth", "UNDER PROCESS"]:
				payment_status = "Pending"
				msg = msg or "Transaction is pending authorization."
			elif "rejected" in status.lower():
				payment_status = "Rejected"
				msg = msg or "Transaction has been rejected."
			else:
				payment_status = "Failured"
				msg = "Unknown status received."

			result[ref_no] = {
				"status": payment_status,
				"utr_number": utr_no,
				"message": msg,
			}

		return result

	def update_account_config(self, method):
		method_map = {
			"make_payment": self.set_payment_data,
			"payment_status": self.set_payment_status_data,
		}

		if method in method_map:
			method_map[method]()

	def set_payment_data(self):
		self.account_config.update(
			{
				"doMultiPaymentCorpReq": {
					"Header": {
						"Maker_ID": self.maker_id,
						"Checker_ID": self.checker_id,
						"Approver_ID": self.approver_id,
					},
					"Body": {
						"Payment": [
							{
								"RefNo": payment.get("name", ""),
								"Amount": payment.get("amount", ""),
								"Debit_Acct_No": self.account_number,
								"Debit_Acct_Name": self.account_holder_name,
								"Debit_Mobile": self.mobile_number or "",
								"Ben_IFSC": "IDFC0001",  # payment.get("branch_code", ""),
								"Ben_Acct_No": payment.get("bank_account_no", ""),
								"Ben_Name": payment.get("party_name", "")
								or payment.get("party", ""),
								"Ben_BankName": payment.get("party_name", "")
								or payment.get("party", ""),
								"Ben_Email": payment.get("email", "") or "",
								"Ben_Mobile": payment.get("mobile_no", "") or "",
								"Mode_of_Pay": "NEFT",
								"Nature_of_Pay": "MPYMT",
								"Remarks": f'Payment from {payment.get("parent", "")} for {payment.get("party_name", "") or payment.get("party", "")}',
							}
							for payment in self.doc.get("summary", [])
						]
					},
				}
			}
		)

	def set_payment_status_data(self):
		self.account_config.update(
			{
				"doMultiPaymentCorpReq": {
					"Header": {
						"Maker_ID": self.maker_id,
						"Checker_ID": self.checker_id,
						"Approver_ID": self.approver_id,
					},
					"Body": {
						"Tran_ID": self.transaction_id,
					},
				}
			}
		)

	@frappe.whitelist()
	def get_api_endpoints(self):
		from india_banking_connector.default import IDFC_ENCRYPTED_END_POINTS
		from india_banking_connector.install import decrypt

		decrypted = decrypt(IDFC_ENCRYPTED_END_POINTS)
		stagin_or_prod = "testing" if self.testing else "production"
		endpoints = decrypted[self.bank][stagin_or_prod]["composite"]

		self.api_endpoints = []
		self.extend(
			"api_endpoints",
			[{"action": action, "url": url} for action, url in endpoints.items()],
		)
