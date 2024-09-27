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

	def is_active(self):
		if not self.active:
			frappe.throw("Connector not active. Please contact admin.")

	@property
	def urls(self):
		if self.bulk_transaction:
			pass
		else:
			if self.testing:
				return frappe._dict({
					"oauth_token": "https://api-uat.hdfcbank.com/auth/oauth/v1/token",
					"make_payment" : "https://api-uat.hdfcbank.com/api/v1/corp-initiatePayment",
					"payment_status" : "https://api-uat.hdfcbank.com/api/v1/corp-paymentInq",
					"generate_otp" : "",
					"bank_balance": "",
					"bank_statement": "",
					"bank_statement_paginated": ""
				})
			else:
				return frappe._dict({
					"oauth_token": "https://api.hdfcbank.com/auth/oauth/v1/token",
					"make_payment" : "https://api.hdfcbank.com/api/v1/corp-initiatePayment",
					"payment_status" : "https://api.hdfcbank.com/api/v1/corp-paymentInq",
					"generate_otp" : "",
					"bank_balance": "",
					"bank_statement": "",
					"bank_statement_paginated": ""
				})

	@property
	def headers(self):
		return {
			"apikey": self.get_password('client_key'),
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

		log_id = create_api_log(
			response, action= "Initiate Payment",
	  		account_config = self.get_account_config("make_payment"),
			ref_doctype= self.payment_doc.parenttype,
			ref_docname= self.payment_doc.parent
		)

		return self.get_decrypted_response(response, method= "make_payment", log_id=log_id)

	def get_payment_status(self):
		url = self.urls.payment_status
		headers = self.headers
		payload = self.get_encrypted_payload(method= 'payment_status')

		response = requests.post(url, headers=headers, data= payload)

		log_id = create_api_log(
			response, action= "Payment Status",
	  		account_config = self.get_account_config("payment_status"),
			ref_doctype= self.payment_doc.parenttype,
			ref_docname= self.payment_doc.parent
		)

		return self.get_decrypted_response(response, method= "payment_status", log_id=log_id)

	def set_decrypted_response(self, log_id, response_data):
		if isinstance(response_data, str):
			response_data = json.loads(response_data)
		response_data = json.dumps(response_data, indent=4)
		if frappe.db.exists("Bank Request Log", log_id):
			frappe.db.set_value("Bank Request Log", log_id,"decrypted_response" , response_data)

	def get_decrypted_response(self, response, method, log_id= None):
		res_dict = frappe._dict({})
		if response.ok:
			if method == "make_payment":
				decrypted_response = self.decrypt_response(response, bank= self.bank)
				self.set_decrypted_response(log_id, decrypted_response)
				if isinstance(decrypted_response, str):
					decrypted_response = json.loads(decrypted_response)
				res_dict.status = 'ACCEPTED'
				res_dict.message = decrypted_response.get('Transaction')
			elif method == "payment_status":
				decrypted_response = self.decrypt_response(response, bank= self.bank)
				self.set_decrypted_response(log_id, decrypted_response)
				if isinstance(decrypted_response, str):
					decrypted_response = json.loads(decrypted_response)

				msg, utr, sts = self.get_msg_utr_number(decrypted_response)

				res_dict.status = sts
				res_dict.message = msg
				res_dict.utr_number = utr
		else:
			res_dict.status = 'Request Failure'
			res_dict.error = response.text

		return res_dict

	def get_msg_utr_number(self, data):
		if "ALL_RECORDS" in data and data["ALL_RECORDS"]:
			record = data["ALL_RECORDS"][0] or {}

			if record:
				if "TXN_STATUS" in record and record["TXN_STATUS"]:
					utr = record.get("UTR_NO", None)
					if not utr and record["TXN_STATUS"] == 'Processed' and record["TRANSFER_TYPE"] == 'Intra Bank Transfer':
						utr = record['PAYMENTREFNO']

					msg, sts = self.get_status_description(record.get("OD_STATUS"))
					return msg, utr, sts
			else:
				raise Exception(f"Error in processing payment status: {data}")
			return

	def get_encrypted_payload(self, method):
		if method == 'make_payment':
			return self.encrypt_payload(self.get_account_config(method), bank= self.bank)
		elif method == 'payment_status':
			return self.encrypt_payload(self.get_account_config(method), bank= self.bank)

	def get_account_config(self, method):
		conector_doc = self
		payment_details = self.payment_doc

		if 'A2A' in payment_details.mode_of_transfer:
			mode_of_transfer = "Intra Bank Transfer"
		else:
			mode_of_transfer = payment_details.mode_of_transfer

		if method == 'make_payment':
			return {
				"LOGIN_ID": conector_doc.login_id,
				"INPUT_GCIF": conector_doc.scope,
				"TRANSFER_TYPE_DESC": mode_of_transfer,
				"BENE_BANK": payment_details.bank,
				"INPUT_DEBIT_AMOUNT": payment_details.amount,
				"INPUT_VALUE_DATE": getdate().strftime("%d/%m/%Y"),
				"TRANSACTION_TYPE": "SINGLE",
				"INPUT_DEBIT_ORG_ACC_NO": conector_doc.account_number,
				"INPUT_BUSINESS_PROD": conector_doc.business_prod,
				"BENE_ID": "",
				"BENE_ACC_NAME": "",
				"BENE_ACC_NO": payment_details.bank_account_no,
				"BENE_TYPE": "ADHOC",
				"BENE_BRANCH": "",
				"BENE_IDN_CODE": payment_details.branch_code,
				"EMAIL_ADDR_VIEW": payment_details.email,
				"PAYMENT_REF_NO": payment_details.name,
			}
		elif method == "payment_status":
			return {
					"LOGIN_ID": conector_doc.login_id,
					"INPUT_GCIF": conector_doc.scope,
					"TXNDATE": getdate(payment_details.payment_date).strftime("%Y-%m-%d"),
					"FILTER1_VALUE_TXT": mode_of_transfer,
					"CBX_API_REF_NO": payment_details.name
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

	def get_status_description(self, od_status):
		return {
			"CI": ("Cancel Requested", "Pending"),
			"D": ("Deleted", "Rejected"),
			"EX": ("Expired", "Failed"),
			"IO": ("Pending Additional Approval", "Pending"),
			"LK": ("Parked", "Pending"),
			"RA": ("Pending Approval", "Pending"),
			"RE": ("Rejected by Entitlement", "Rejected"),
			"RN": ("Rule Setup Required", "Pending"),
			"RO": ("Rejected by Verifier / Approver", "Rejected"),
			"RR": ("Pending Release", "Pending"),
			"RV": ("Pending Verification", "Pending"),
			"TXBVSU": ("Transaction Business Validation Successful", "Pending"),
			"TXCOMP": ("Payment Completed", "Processed"),
			"TXDBPR": ("Debit in progress", "Pending"),
			"TXPDST": ("Pending for Settlement", "Processed"),
			"TXREJE": ("Payment Rejected", "Rejected"),
			"TXVLSU": ("Processed", "Processed"),
			"TXWRHD": ("Payment Warehoused", "Pending"),
			"TXAWRB": ("Transaction Awaiting Rebulking", "Pending"),
			"TXEXPD": ("Transaction Expired", "Failed"),
			"TXSIP": ("Settlement in Progress", "Pending"),
			"DEBFL": ("Debit Failed", "Failed"),
			"DEBREJE": ("Debit Rejected", "Rejected"),
			"MANREJE": ("Manually Rejected", "Rejected")
		}.get(od_status, (f"{od_status} Description Not Available", ""))
