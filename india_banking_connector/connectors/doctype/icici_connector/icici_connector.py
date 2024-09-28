# Copyright (c) 2024, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

import frappe
from india_banking_connector.india_banking_connector.doctype.bank_request_log.bank_request_log import create_api_log
from india_banking_connector.connectors.bank_connector import BankConnector
import requests, json
from base64 import b64decode, b64encode
from frappe.utils import cstr, getdate

class ICICIConnector(BankConnector):
	bank = "ICICI Bank"
	IV = "0000000000000000".encode("utf-8")
	AES_KEY = "1234567887654321".encode("utf-8")
	BLOCK_SIZE = 16

	__all__ = ['intiate_payment', 'get_payment_status']

	def __init__(self, *args, **kwargs):
		kwargs.update(bank = self.bank)
		kwargs.update(block_size = self.BLOCK_SIZE)
		kwargs.update(iv = self.IV)
		kwargs.update(aes_key = self.AES_KEY)

		super().__init__(*args, **kwargs)

		self.bulk_transaction = kwargs.get('bulk_transaction')
		self.doc = frappe._dict(kwargs.get('doc', {}))
		self.payment_doc = frappe._dict(kwargs.get('payment_doc', {}))

	def is_active(self):
		if not self.active:
			frappe.throw("Connector inactive. Please contact admin.")

	@property
	def urls(self):
		if self.bulk_transaction:
			pass
		else:
			if self.testing:
				return frappe._dict({
					"host": "apibankingonesandbox.icicibank.com",
					"oauth_token": "",
					"make_payment" : "https://apibankingonesandbox.icicibank.com/api/v1/composite-payment",
					"payment_status" : "https://apibankingonesandbox.icicibank.com/api/v1/composite-status",
					"generate_otp" : "",
					"bank_balance": "",
					"bank_statement": "",
					"bank_statement_paginated": ""
				})
			else:
				return frappe._dict({
					"host": "apibankingone.icicibank.com",
					"oauth_token": "",
					"make_payment" : "https://apibankingone.icicibank.com/api/v1/composite-payment",
					"payment_status" : "https://apibankingone.icicibank.com/api/v1/composite-status",
					"generate_otp" : "",
					"bank_balance": "",
					"bank_statement": "",
					"bank_statement_paginated": ""
				})


	def headers(self, mode_of_transfer=None):
		return {
			"accept": "application/json",
			"content-type": "application/json",
			"apikey": self.get_password('client_key'),
			"": self,
			"host": self.urls.host,
			"x-priority": self.get_priority(mode_of_transfer)
		}

	def intiate_payment(self):
		url = self.urls.make_payment
		mode_of_transfer = self.payment_doc.mode_of_transfer
		headers = self.headers(mode_of_transfer)
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
		payment_details = self.payment_doc
		url = self.urls.payment_status
		mode_of_transfer = payment_details.mode_of_transfer
		headers = self.headers(mode_of_transfer)
		payload = self.get_encrypted_payload(method= 'payment_status')

		response = requests.post(url, headers=headers, data= payload)

		log_id = create_api_log(
			response, action= "Payment Status",
	  		account_config = self.get_account_config("payment_status"),
			ref_doctype= self.payment_doc.parenttype,
			ref_docname= self.payment_doc.parent
		)

		return self.get_decrypted_response(response, method= "payment_status", log_id=log_id)

	def get_priority(self, mode_of_transfer):
		if mode_of_transfer == "RTGS":
			return "0001"
		elif mode_of_transfer == "IMPS":
			return "0100"
		else:
			return "0010"

	def get_encrypted_payload(self, method):
		connector_doc = self
		payment_details = self.payment_doc
		encrypted_key = self.rsa_encrypt_key(self.AES_KEY, self.get_file_relative_path(connector_doc.public_key)),
		data = self.get_account_config(method)
		payment_payload = {
			"requestId": payment_details.name,
			"service": "",
			"oaepHashingAlgorithm": "NONE",
			"encryptedKey": encrypted_key,
			"encryptedData": self.rsa_encrypt_data(data, encrypted_key ),
			"clientInfo": "",
			"optionalParam": "",
			"iv": b64encode(self.IV).decode("utf-8")
		}

		return json.dumps(payment_payload)

	def get_account_config(self, method):
		payment_details = self.payment_doc

		if 'A2A' in payment_details.mode_of_transfer:
			payment_details.mode_of_transfer = "Intra Bank Transfer"

		data = {}
		if method == "make_payment":
			self.set_payment_data(data, payment_details)
		elif method == "payment_status":
			self.set_payment_status_data(data, payment_details)

		return data

	def set_payment_data(self, data):
		connector_doc = self
		payment_details = self.payment_doc
		bank_doc = self.doc

		if payment_details.mode_of_transfer == "RTGS":
			data.update({
				"AGGRID": connector_doc.aggr_id,
				"CORPID": connector_doc.corp_id,
				"USERID": connector_doc.corp_usr,
				"URN": connector_doc.urn,
				"AGGRNAME": connector_doc.aggr_name,
				"UNIQUEID": payment_details.name,
				"DEBITACC": connector_doc.account_number,
				"CREDITACC": payment_details.bank_account_no,
				"IFSC": payment_details.branch_code,
				"AMOUNT": cstr(payment_details.amount),
				"CURRENCY": "INR",
				"TXNTYPE": "TPA" if payment_details.bank == "ICICI Bank" else "RTG",
				"PAYEENAME": payment_details.account_name,
				"REMARKS": f"{payment_details.party_type} - {payment_details.party}",
				"WORKFLOW_REQD": "N"
			})

		elif payment_details.mode_of_transfer == "IMPS":
			if not connector_doc.enable_imps:
				res_dict = frappe._dict({})
				res_dict.status = "Request Failure"
				res_dict.message = "IMPS is not enabled for this {} account.".format(connector_doc.account_number)
				return
			data ={
				"localTxnDtTime": frappe.utils.now_datetime().strftime("%Y%m%d%H%M%S"),
				"beneAccNo": payment_details.bank_account_no,
				"beneIFSC": payment_details.branch_code,
				"amount": cstr(payment_details.amount),
				"tranRefNo": payment_details.name,
				"paymentRef": payment_details.name,
				"senderName": bank_doc.company_bank_account_name,
				"mobile": bank_doc.mobile_number,
				"retailerCode": connector_doc.retailer_code,
				"passCode": connector_doc.pass_code,
				"bcID": connector_doc.bcid,
				"aggrId": connector_doc.aggr_id,
				"crpId": connector_doc.corp_id,
				"crpUsr": connector_doc.corp_usr
				}

			frappe.log_error("Data - IMPS", data )
		else:
			data = {
				"tranRefNo": payment_details.name,
				"amount": cstr(payment_details.amount),
				"senderAcctNo": connector_doc.account_number,
				"beneAccNo": payment_details.bank_account_no,
				"beneName": payment_details.account_name,
				"beneIFSC": payment_details.branch_code,
				"narration1": payment_details.party_name,
				"narration2": connector_doc.aggr_id,
				"crpId": connector_doc.corp_id,
				"crpUsr": connector_doc.corp_usr,
				"aggrId": connector_doc.aggr_id,
				"urn": connector_doc.urn,
				"aggrName": connector_doc.aggr_name,
				"txnType": "TPA" if payment_details.bank == "ICICI Bank" else "RTG",
				"WORKFLOW_REQD": "N"
			}
			frappe.log_error("Data - NEFT", data )

	def set_payment_status_data(self):
		payment_details = self.payment_doc
		connector_doc = self.doc
		if payment_details.mode_of_transfer == "IMPS":
			return {
				"transRefNo": payment_details.name,
				"date": payment_details.payment_date,
				"recon360": "N",
				"passCode": connector_doc.pass_code,
				"bcID": connector_doc.bcid
			}

		return {
			"AGGRID": connector_doc.aggr_id,
			"CORPID": connector_doc.corp_id,
			"USERID": connector_doc.corp_usr,
			"URN": connector_doc.urn,
			"UNIQUEID": payment_details.name
		}


	def get_decrypted_response(self, response, method, log_id= None):
		connector_doc = self
		res_dict = frappe._dict({})
		if response.ok:
			response=json.loads(response.text)
			decrypted_key= self.rsa_decrypt_key(response.get("encryptedKey"), connector_doc)
			decrypted_data = self.rsa_decrypt_data(response.get('encryptedData'), decrypted_key.encode("utf-8"))

			self.set_decrypted_response(log_id, decrypted_data)
			if method == "make_payment" and decrypted_data:
				if isinstance(decrypted_data, str):
					decrypted_response =json.loads(decrypted_data)

				response= frappe._dict(decrypted_response)
				if response.STATUS == "SUCCESS":
					res_dict.status = "ACCEPTED"
					res_dict.message = response.MESSAGE
				elif response.STATUS == "PENDING":
					res_dict.status = "ACCEPTED"
					res_dict.message = response.MESSAGE
				elif response.STATUS == "DUPLICATE":
					res_dict.status = "FAILURE"
					res_dict.message = response.MESSAGE
				elif  response.errorCode == "997":
					res_dict.status = "Request Failure"
					res_dict.message = response.errorCode + " : " + response.description
				else:
					res_dict.status = "FAILURE"
					res_dict.message = response.MESSAGE

			elif method == "payment_status" and decrypted_data:
				if isinstance(decrypted_data, str):
					decrypted_response = json.loads(decrypted_data)
				response= frappe._dict(decrypted_response)

				if response.STATUS == "SUCCESS":
						res_dict.status = "Processed"
						res_dict.reference_number = response.UTRNUMBER
						res_dict.message = "Success"
				elif response.STATUS == "PENDING":
						res_dict.status = "Pending"
						res_dict.message = response.MESSAGE
				else:
						res_dict.status = "FAILURE"
						res_dict.message = response.MESSAGE

		else:
			res_dict.status = "Request Failure"
			res_dict.message = response.text or response.status_code

		return res_dict

	def set_decrypted_response(self, log_id, response_data):
		if isinstance(response_data, str):
			response_data = json.loads(response_data)
		response_data = json.dumps(response_data, indent=4)
		if frappe.db.exists("Bank Request Log", log_id):
			frappe.db.set_value("Bank Request Log", log_id,"decrypted_response" , response_data)

	def get_cert(self):
		return (self.get_file_relative_path(self.cert_file), self.get_file_relative_path(self.private_key))

	def get_transaction_history(self):
		return "Transaction History Not Implemented"

	def get_balance(self):
		return "Balance Not Implemented"
