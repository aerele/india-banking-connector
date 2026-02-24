# Copyright (c) 2025, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

import json

import frappe
import requests
from frappe import _
from frappe.query_builder import DocType
from frappe.utils import cint, cstr, flt, get_datetime, getdate

from india_banking_connector.connectors.bank_connector import BankConnector
from india_banking_connector.india_banking_connector.doctype.bank_request_log.bank_request_log import (
	create_api_log,
)


class UnionBankConnector(BankConnector):
	__all__ = [
		"get_oauth_token",
		"initiate_payment",
		"get_payment_status",
		"get_bank_balance",
		"get_bank_statement",
	]

	def __init__(self, *args, **kwargs):
		self.bank = "Union Bank of India"
		super().__init__(*args, **kwargs)

		self.bulk_transaction = kwargs.get("bulk_transaction")
		self.doc = frappe._dict(kwargs.get("doc", {}))
		self.payment_doc = frappe._dict(kwargs.get("payment_doc", {}))

		self.account_config = {}

	def update_aes_and_iv(self):
		self.AES_KEY = self.get_password("aes_key").encode("utf-8")
		self.IV = self.get_password("iv").encode("utf-8")

	@property
	def urls(self):
		self.update_aes_and_iv()

		UBC = DocType(self.doctype)
		EU = DocType("Endpoint URLs")
		urls = (
			frappe.qb.from_(UBC)
			.join(EU)
			.on(EU.parent == self.name)
			.select(EU.action, EU.url)
			.orderby(EU.idx)
		).run()

		return frappe._dict(dict(urls))

	def headers(self, action=None):
		headers = {"Content-Type": "application/json"}
		if action != "Oauth Token":
			token = (self.get_oauth_token("Oauth Token") or {}).get("token")
			if not token:
				frappe.throw("Failed to get Oauth Token")

			headers.update({"Authorization": "Bearer {}".format(token)})
		return headers

	def get_message_id(self, length=15):
		return frappe.generate_hash(
			get_datetime().strftime("%Y%m%d%H%M%S"), length=length
		)

	def get_oauth_token(self, action):
		payment_details = self.payment_doc

		url = self.urls.oauth_token
		headers = self.headers(action)
		encrypted_payload = self.get_encrypted_payload(method="oauth_token")

		payload = {
			"reqdata": encrypted_payload,
			"msgid": self.get_message_id(),
		}

		response = requests.post(url, headers=headers, data=json.dumps(payload))

		log_id = create_api_log(
			response,
			action="Oauth Token",
			account_config=self.account_config,
			ref_doctype=payment_details.parenttype,
			ref_docname=payment_details.parent,
			connector=self,
		)

		return self.get_decrypted_response(
			response, method="oauth_token", log_id=log_id
		)

	def initiate_payment(self):
		payment_details = self.payment_doc
		unique_id = payment_details.name

		if existing_payment_response := self.validate_duplicate_payments(
			unique_id=unique_id
		):
			return existing_payment_response

		url = self.urls.make_payment
		headers = self.headers()
		encrypted_payload = self.get_encrypted_payload(method="make_payment")

		payload = {
			"reqdata": encrypted_payload,
			"msgid": self.get_message_id(),
		}

		response = requests.post(url, headers=headers, data=json.dumps(payload))

		log_id = create_api_log(
			response,
			action="Initiate Payment",
			account_config=self.account_config,
			ref_doctype=payment_details.parenttype,
			ref_docname=payment_details.parent,
			unique_id=unique_id,
			connector=self,
		)

		return self.get_decrypted_response(
			response, method="make_payment", log_id=log_id
		)

	def get_payment_status(self):
		payment_details = self.payment_doc
		unique_id = payment_details.name

		url = self.urls.payment_status
		headers = self.headers()
		encrypted_payload = self.get_encrypted_payload(method="payment_status")

		payload = {
			"reqdata": encrypted_payload,
			"msgid": self.get_message_id(),
		}

		response = requests.post(url, headers=headers, data=json.dumps(payload))

		log_id = create_api_log(
			response,
			action="Payment Status",
			account_config=self.account_config,
			ref_doctype=payment_details.parenttype,
			ref_docname=payment_details.parent,
			unique_id=unique_id,
			connector=self,
		)

		return self.get_decrypted_response(
			response, method="payment_status", log_id=log_id
		)

	def get_bank_balance(self):
		if not self.balance_check:
			frappe.throw(_("Bank Balance is disabled."))

		payment_details = self.payment_doc
		unique_id = payment_details.name

		url = self.urls.bank_balance
		headers = self.headers()
		encrypted_payload = self.get_encrypted_payload(method="bank_balance")

		payload = {
			"reqdata": encrypted_payload,
			"msgid": self.get_message_id(),
		}

		response = requests.post(url, headers=headers, data=json.dumps(payload))

		log_id = create_api_log(
			response,
			action="Bank Balance",
			account_config=self.account_config,
			ref_doctype=self.doctype,
			ref_docname=self.name,
			unique_id=unique_id,
			connector=self,
		)

		return self.get_decrypted_response(
			response, method="bank_balance", log_id=log_id
		)

	def get_bank_statement(self):
		if not self.statement_fetch:
			frappe.throw(_("Statement fetch is disabled."))

		payment_details = self.payment_doc
		unique_id = payment_details.name

		url = self.urls.bank_statement
		headers = self.headers()
		encrypted_payload = self.get_encrypted_payload(method="bank_statement")

		payload = {
			"reqdata": encrypted_payload,
			"msgid": self.get_message_id(),
		}

		response = requests.post(url, headers=headers, data=json.dumps(payload))

		log_id = create_api_log(
			response,
			action="Bank Statement",
			account_config=self.account_config,
			ref_doctype=self.doctype,
			ref_docname=self.name,
			unique_id=unique_id,
			connector=self,
		)

		return self.get_decrypted_response(
			response, method="bank_statement", log_id=log_id
		)

	def update_account_config(self, method):
		method_map = {
			"oauth_token": self.set_oauth_data,
			"make_payment": self.set_payment_data,
			"payment_status": self.set_payment_status_data,
			"bank_balance": self.set_balance_data,
			"bank_statement": self.set_statement_data,
		}

		if method in method_map:
			method_map[method]()  # update payload details

	def get_encrypted_payload(self, method):
		self.update_account_config(method)
		return self.aes_encrypt_data(self.account_config, self.AES_KEY)

	def get_decrypted_response(self, response, method, log_id=None):
		self.update_aes_and_iv()
		res_dict = frappe._dict({})
		if response.ok:
			decrypted_data = self.aes_decrypt_data(response.text, self.AES_KEY)
			self.set_decrypted_response(log_id, decrypted_data)
			self.get_formated_response(decrypted_data, res_dict, method)
		else:
			res_dict.status = "Request Failure"
			res_dict.message = response.text or response.status_code

		return res_dict

	def set_decrypted_response(self, log_id, response_data):
		if isinstance(response_data, str):
			response_data = json.loads(response_data)

		response_data = json.dumps(response_data, indent=4)

		super().set_decrypted_response(log_id, response_data)

	def set_oauth_data(self):
		self.account_config.update(
			{
				"requestType": "0",
				"msgid": self.get_message_id(),
				"data": {
					"username": self.user_name,
					"password": self.get_password("password"),
				},
			}
		)

	def set_payment_data(self):
		payment_details = self.payment_doc
		self.account_config.update(
			{
				"requestType": "0",
				"msgid": self.get_message_id(),
				"data": {
					"type": "account",
					"senderCode": self.sender_code,
					"transactionId": payment_details.name,
					"beneficiaryAccNo": payment_details.bank_account_no,
					"beneficiaryAccName": payment_details.party_name
					or payment_details.party,
					"beneficiaryAddress": "India",
					"beneficiaryBankIFSCCode": payment_details.branch_code,
					"beneficiaryMobileNumber": payment_details.mobile_no,
					"beneficiaryEmailId": payment_details.email,
					"transactionAmount": cstr(payment_details.amount),
					"transactionDate": getdate().strftime("%Y%m%d"),
					"remitterAccNo": self.account_number,
					"remitterName": self.sender_name,
					"remitterAddress": "India",
					"countryCode": "IND",
					"remitterMobileNumber": self.mobile_number,
					"remitterEmailId": self.email_id,
					"purpose": "P08",
				},
			}
		)

	def set_payment_status_data(self):
		self.account_config.update(
			{
				"requestType": "0",
				"msgid": self.get_message_id(),
				"data": {
					"type": "account",
					"senderCode": self.sender_code,
					"transactionId": self.payment_doc.name,
				},
			}
		)

	def set_balance_data(self):
		self.account_config.update(
			{
				"requestType": "0",
				"msgid": self.get_message_id(),
				"data": {
					"type": "account",
					"accountNumber": self.account_number,
					"senderCode": self.sender_code,
				},
			}
		)

	def set_statement_data(self):
		payload_details = self.doc
		start_date = getdate(payload_details.get("from_date", "")).strftime("%d-%m-%Y")
		end_date = getdate(payload_details.get("to_date", "")).strftime("%d-%m-%Y")

		self.account_config.update(
			{
				"requestType": "0",
				"msgid": self.get_message_id(),
				"data": {
					"type": "account",
					"accNum": self.account_number,
					"startDate": start_date,
					"endDate": end_date,
				},
			}
		)

	def get_formated_response(self, data, res_dict, method):
		if isinstance(data, str):
			data = json.loads(data)

		data = frappe._dict(data)

		if method == "oauth_token" and data:
			res_dict.update(data.get("data", {}))

		elif method == "make_payment" and data:
			if data.status == "00":
				res_dict.payment_status = "ACCEPTED"
				response_data = frappe._dict(data.get("data", {}))
				if response_data.responseCode == "000":
					res_dict.summary_details = {
						self.payment_doc.name: {"payment_status": "Accepted"}
					}
				else:
					res_dict.summary_details = {
						self.payment_doc.name: {
							"payment_status": "Failed",
							"message": response_data.status,
							"error_code": response_data.responseCode,
						}
					}
			else:
				res_dict.status = "Failed"
				res_dict.message = data.get("errorMsg")

		elif method == "payment_status":
			if data.status == "00":
				res_dict.payment_status = "PROCESSED"
				response_data = frappe._dict(data.get("data", {}))
				payment_status = self.get_status_details(response_data.responseCode)
				if response_data.responseCode == "000":
					utr_number = response_data.NeftRefId
					if self.payment_doc.bank == self.bank:
						utr_number = self.payment_doc.name
					res_dict.summary_details = {
						self.payment_doc.name: {
							"status": payment_status,
							"utr_number": utr_number,
							"processed_date": get_datetime(
								response_data.transactionTime
							).strftime("%Y-%m-%d"),
							"message": response_data.status or "Payment Completed",
						}
					}
				elif not response_data.responseCode:
					res_dict.summary_details = {
						self.payment_doc.name: {
							"status": payment_status,
							"response": response_data,
						}
					}
				else:
					res_dict.summary_details = {
						self.payment_doc.name: {
							"status": payment_status,
							"message": response_data.status,
							"error_code": response_data.responseCode,
						}
					}
			else:
				res_dict.status = "Failed"
				res_dict.message = data.get("errorMsg")

		elif method == "bank_balance":
			if data.status == "00":
				response_data = frappe._dict(data.get("data", {}))
				if response_data.responseCode == "000":
					res_dict.server_status = "Success"
					res_dict.balance = response_data.get("amount", {}).get(
						"AvailBal", 0
					)
					res_dict.date = get_datetime(data.get("msgtime", "")).strftime(
						"%Y-%m-%d"
					)
				else:
					res_dict.status = "Failed"
					res_dict.message = response_data.get("status")
			else:
				res_dict.status = "Failed"
				res_dict.message = data.get("errorMsg")

		elif method == "bank_statement":
			if data.status == "00":
				transactions = []
				response_data = frappe._dict(data.get("data", {}))
				if cint(response_data.txnCount) > 0:
					for txn in response_data.get("transactionDetails", []):
						amount = abs(flt(txn.get("tranAmount")))
						if txn.get("drCRIndicator").lower() == "d":
							amount = -1 * amount
						transaction = {
							"transaction_date": txn.get("tranDate", ""),
							"transaction_amount": amount,
							"reference_number": txn.get("tranId"),
							"transaction_description": txn.get("tranParticulars", ""),
						}
						transactions.append(transaction)
					res_dict.server_status = "Success"
					res_dict.bank_statements = transactions
				else:
					res_dict.status = "Failed"
					res_dict.message = response_data.get("status")
			else:
				res_dict.status = "Failed"
				res_dict.message = data.get("errorMsg")

	def get_status_details(self, status_code):
		rejected_status_code = [
			"114",
			"115",
			"509",
			"513",
			"514",
			"515",
			"516",
			"517",
			"518",
			"519",
			"521",
			"526",
			"527",
			"529",
			"531",
			"532",
			"533",
			"536",
			"539",
			"114",
			"111",
			"116",
			"904",
			"996",
			"914",
			"999",
			"101",
			"103",
			"105",
			"106",
			"107",
			"108",
			"109",
			"110",
			"112",
			"113",
			"114",
			"120",
			"125",
			"189",
			"203",
			"204",
			"205",
			"206",
			"301",
			"302",
		]
		failed_status_code = [
			"902",
			"615",
			"119",
			"121",
			"180",
			"185",
			"913",
			"501",
			"505",
			"522",
			"525",
			"904",
			"913",
		]
		pending_status_code = [
			"009",
			"538",
			"906",
			"907",
			"908",
			"909",
			"911",
			"991",
			"998",
			"401",
			"601",
		]

		if status_code == "000":
			return "Processed"
		elif status_code in rejected_status_code:
			return "Rejected"
		elif status_code in failed_status_code:
			return "Failed"
		elif status_code in pending_status_code:
			return "Pending"

	@frappe.whitelist()
	def get_api_endpoints(self):
		from india_banking_connector.default import UBI_ENCRYPTED_END_POINTS
		from india_banking_connector.install import decrypt

		decrypted = decrypt(UBI_ENCRYPTED_END_POINTS)
		stagin_or_prod = "testing" if self.testing else "production"
		endpoints = decrypted[self.bank][stagin_or_prod]["composite"]

		self.api_endpoints = []
		self.extend(
			"api_endpoints",
			[{"action": action, "url": url} for action, url in endpoints.items()],
		)
