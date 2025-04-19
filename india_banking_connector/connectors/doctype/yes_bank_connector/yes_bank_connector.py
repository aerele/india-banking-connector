# Copyright (c) 2024, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

import frappe
from frappe.model.document import Document
from india_banking_connector.india_banking_connector.doctype.bank_request_log.bank_request_log import create_api_log
from india_banking_connector.connectors.bank_connector import BankConnector
import india_banking_connector.utils as utils
import json, base64, requests


class YESBANKConnector(BankConnector):
	bank = "YES Bank"

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

	def intiate_payment(self):
		url = self.urls.make_payment
		headers = self.headers
		payload = self.get_payload(method= 'make_payment')
		response = requests.post(url, headers=headers, data= payload, cert= self.get_cert())

		create_api_log(
			response, action= "Initiate Payment",
			account_config = self.get_payload(method= 'make_payment'),
			ref_doctype= self.payment_doc.doctype,
			ref_docname= self.payment_doc.name
		)

		return self.get_verified_response(response, method= "make_payment")

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

		return self.get_verified_response(response, method= "payment_status")

	@property
	def urls(self):
		if self.bulk_transaction:
			pass
		else:
			if self.testing:
				return frappe._dict({
					"oauth_token": "",
					"make_payment" : "https://uatskyway.yesbank.in/app/uat/api-banking/domestic-payments",
					"payment_status" : "https://uatskyway.yesbank.in/app/uat/api-banking/payment-details",
					"generate_otp" : "",
					"bank_balance": "",
					"bank_statement": "",
					"bank_statement_paginated": ""
				})
			else:
				return frappe._dict({
					"oauth_token": "",
					"make_payment" : "",
					"payment_status" : "",
					"generate_otp" : "",
					"bank_balance": "",
					"bank_statement": "",
					"bank_statement_paginated": ""
				})

	@property
	def headers(self):
		return {
			'X-IBM-Client-Id': self.get_password('client_key'),
			'X-IBM-Client-Secret': self.get_password('client_secret'),
			'Authorization': self.get_authorization(self.get_password('user_name'), self.get_password('password')),
			'Content-Type': 'application/json'
		}

	def get_authorization(self, usr, pwd):
		auth_string = usr + ":" + pwd
		encoded_credintial = "Basic "+ base64.b64encode(auth_string.encode()).decode()
		return encoded_credintial

	def get_payload(self, method):
		if method == 'make_payment':
			return self.get_payment_payload()
		elif method == 'payment_status':
			return self.get_status_payload()

	def get_payment_payload(self):
		conector_doc = self
		payment_details = self.payment_doc

		if 'A2A' in payment_details.mode_of_transfer:
			mode_of_transfer = "FT"
		else:
			mode_of_transfer = payment_details.mode_of_transfer

		return json.dumps(
		{
			"Data": {
				"ConsentId": conector_doc.user_id,
				"Initiation": {
					"InstructionIdentification": payment_details.name,
					"EndToEndIdentification": "",
					"InstructedAmount": {
						"Amount": payment_details.amount,
						"Currency": "INR"
					},
					"DebtorAccount": {
						"Identification": conector_doc.account_number,
						"SecondaryIdentification": conector_doc.user_id
					},
					"CreditorAccount": {
						"SchemeName": payment_details.branch_code,
						"Identification": payment_details.bank_account_no,
						"Name": payment_details.party,
						"Unstructured": {
							"ContactInformation": {
								"EmailAddress": payment_details.email,
								"MobileNumber": payment_details.get('mobile_no', '')
							}
						}
					},
					"RemittanceInformation": {
						"Reference": payment_details.name,
						"Unstructured": {
							"CreditorReferenceInformation": "RemeToBeneInfo"
						}
					},
					"ClearingSystemIdentification": mode_of_transfer
				}
			},
			"Risk": {
				"DeliveryAddress": json.loads(payment_details.get('address', '{}')),
			}
		}
	)

	def get_status_payload(self):
		conector_doc = self
		payment_details = self.payment_doc
		return json.dumps({
			"Data": {
				"InstrId": payment_details.name,
				"ConsentId": conector_doc.user_id,
				"SecondaryIdentification": conector_doc.user_id
			}
		}
	)

	def get_verified_response(self, response, method):
		res_dict = frappe._dict({})
		if response.ok:
			if method == "make_payment":
				response_data = json.loads(response.text)

				if "Data" in response_data and response_data["Data"]:
					if "Status" in response_data["Data"] and response_data["Data"]["Status"]:
						response_status = response_data["Data"]["Status"]
						if response_status == "Duplicate":
							res_dict.status = 'Failed'
							res_dict.message = "Dublicate Payment"
						elif response_status == "Received":
							res_dict.status = 'ACCEPTED'
							res_dict.message = "Payment Initiated"

			elif method == "payment_status":
				response_data = json.loads(response.text)

				msg, utr, sts = self.get_msg_utr_number(response_data)

				res_dict.status = sts
				res_dict.message = msg
				res_dict.utr_number = utr
		else:
			res_dict.status = 'Request Failure'
			res_dict.error = response.text

		return res_dict

	def get_msg_utr_number(self, data):
		msg, utr, sts = "Payment Status Not Available", None, "Failed"

		if "Data" in data and data["Data"]:
			if "Initiation" in data["Data"] and data["Data"]["Initiation"]:
				if "EndToEndIdentification" in data["Data"]["Initiation"] and data["Data"]["Initiation"]["EndToEndIdentification"]:
					utr = data["Data"]["Initiation"]["EndToEndIdentification"]
			if "Status" in data["Data"] and data["Data"]["Status"]:
				msg = data["Data"]["Status"]
				if data in ["SettlementInProcess", "Pending"]:
					sts = "Approval Pending"
				elif data == "SettlementCompleted":
					sts = "Processed"
				elif data in ["SettlementReversed", "FAILED"]:
					sts = "Failed"

		return msg, utr, sts

	def get_cert(self):
		return (self.get_file_relative_path(self.cert_file), self.get_file_relative_path(self.private_key))

	def get_transaction_history(self):
		return "Transaction History Not Implemented"

	def get_balance(self):
		return "Balance Not Implemented"