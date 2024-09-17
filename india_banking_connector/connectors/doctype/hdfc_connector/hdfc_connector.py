# Copyright (c) 2024, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

import frappe, requests, json
from frappe.utils import getdate
from india_banking_connector.connectors.bank_connector import BankConnector
import india_banking_connector.utils as utils
from india_banking_connector.india_banking_connector.doctype.bank_request_log.bank_request_log import create_api_log
import base64

class HDFCConnector(BankConnector):
	bank = "HDFC Bank"

	__all__ = ['intiate_payment', 'get_payment_status']

	def __init__(self, *args, **kwargs):
		kwargs.update(bank = self.bank)
		super().__init__(*args, **kwargs)

		self.bulk_transaction = kwargs.get('bulk_transaction')
		self.doc = frappe._dict(kwargs.get('doc', {}))
		self.payment_doc = frappe._dict(kwargs.get('payment_doc', {}))

	@property
	def urls(self):
		if self.bulk_transaction:
			pass
		else:
			return frappe._dict({
				"oauth_token": "https://api-uat.hdfcbank.com/auth/oauth/v1/token",
				"make_payment" : "https://api-uat.hdfcbank.com/api/v1/corp-initiatePayment",
				"payment_status" : "https://api-uat.hdfcbank.com/api/v1/corp-paymentInq",
				"generate_otp" : "",
				"bank_balance": "",
				"bank_statement": "",
				"bank_statement_paginated": ""
			})

	@property
	def headers(self):
		return {
			"apikey": self.apikey,
			"scope": self.scope,
			"transactionId": utils.get_id(),
			"Content-Type": "application/jose",
			"Authorization": "Bearer "+ self.get_oauth_token()
		}

	def intiate_payment(self):
		url = self.urls.make_payment
		headers = self.headers
		payload = self.get_encrypted_payload(method= 'make_payment')

		response = requests.post(url, headers=headers, data= payload)

		create_api_log(
			response, action= "Initiate Payment",
	  		account_config = self.get_account_config("make_payment"),
			ref_doctype= self.payment_doc.doctype,
			ref_docname= self.payment_doc.name
		)

		return self.get_decrypted_response(response, method= "make_payment")

	def get_payment_status(self):
		url = self.urls.payment_status
		headers = self.headers
		payload = self.get_encrypted_payload(method= 'payment_status')

		response = requests.post(url, headers=headers, data= payload)

		create_api_log(
			response, action= "Payment Status",
	  		account_config = self.get_account_config("payment_status"),
			ref_doctype= self.payment_doc.doctype,
			ref_docname= self.payment_doc.name
		)

		return self.get_decrypted_response(response, method= "payment_status")

	def get_decrypted_response(self, response, method):
		res_dict = frappe._dict({})
		if response.ok:
			if method == "make_payment":
				decrypted_response = self.decrypt_response(response, bank= self.bank)
				if isinstance(decrypted_response, str):
					decrypted_response = json.loads(decrypted_response)
				res_dict.status = 'success'
				res_dict.message = decrypted_response.get('Transaction')
			elif method == "payment_status":
				decrypted_response = self.decrypt_response(response, bank= self.bank)
				if isinstance(decrypted_response, str):
					decrypted_response = json.loads(decrypted_response)
				res_dict.status = 'success'
				msg, utr = self.get_msg_utr_number(decrypted_response)
				if not utr:
					res_dict.status = 'error'
				res_dict.message = msg
				res_dict.utr_number = utr
		else:
			res_dict.status = 'failed'
			res_dict.error = response.text

		return res_dict

	def get_msg_utr_number(self, data):
		if "ALL_RECORDS" in data:
			records = data.get("ALL_RECORDS")
			if records:
				record = records[0]
				utr = record.get("UTR_NO")
				msg = record.get("TXN_STATUS")
				return msg, utr
		return "Transaction Status Not Available", ""

	def get_encrypted_payload(self, method):
		if method == 'make_payment':
			return self.encrypt_payload(self.get_account_config(method), bank= self.bank)
		elif method == 'payment_status':
			return self.encrypt_payload(self.get_account_config(method), bank= self.bank)

	def get_account_config(self, method):
		conector_doc = self
		payment_details = self.payment_doc
		if method == 'make_payment':
			return {
				"LOGIN_ID": conector_doc.login_id,
				"INPUT_GCIF": conector_doc.scope,
				"TRANSFER_TYPE_DESC": payment_details.mode_of_payment,
				"BENE_BANK": payment_details.bank,
				"INPUT_DEBIT_AMOUNT": payment_details.amount,
				"INPUT_VALUE_DATE": getdate().strftime("%d/%m/%Y"),
				"TRANSACTION_TYPE": "SINGLE",
				"INPUT_DEBIT_ORG_ACC_NO": conector_doc.account_number,
				"INPUT_BUSINESS_PROD": "",
				"BENE_ID": "",
				"BENE_ACC_NAME": "",
				"BENE_ACC_NO": payment_details.bank_account_no,
				"BENE_TYPE": "ADHOC",
				"BENE_BRANCH": "",
				"BENE_IDN_CODE": payment_details.branch_code,
				"EMAIL_ADDR_VIEW": payment_details.email,
				"PAYMENT_REF_NO": conector_doc.doc.name
			}
		elif method == "payment_status":
			return {
					"LOGIN_ID": conector_doc.login_id,
					"INPUT_GCIF": conector_doc.scope,
					"TXNDATE": getdate(payment_details.payment_date).strftime("%Y-%m-%d"),
					"FILTER1_VALUE_TXT": payment_details.mode_of_payment,
					"CBX_API_REF_NO": conector_doc.doc.name
				}


	def get_oauth_token(self):
		params = {
			"grant_type": "client_credentials",
			"scope": self.scope
		}

		auth_string = self.get_password('client_key') + ":" + self.get_password('client_secret')
		encoded_credintial = "Basic "+ base64.b64encode(auth_string.encode()).decode()

		headers = {
			'Content-Type': 'application/x-www-form-urlencoded',
			'Authorization': encoded_credintial
		}

		response = requests.post(self.urls.oauth_token, params= params, headers= headers, cert= self.get_cert())

		create_api_log(response, action=  "Get OAuth Token")

		if response.ok:
			return response.json().get('access_token')
		else:
			frappe.throw('Error in getting OAuth Token. Please check your credentials.')

	def get_cert(self):
		return (self.get_file_relative_path(self.cert_file), self.get_file_relative_path(self.private_key))

	def get_transaction_history(self):
		return "Transaction History Not Implemented"

	def get_balance(self):
		return "Balance Not Implemented"