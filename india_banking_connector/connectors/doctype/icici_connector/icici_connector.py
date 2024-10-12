# Copyright (c) 2024, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

import frappe
from india_banking_connector.india_banking_connector.doctype.bank_request_log.bank_request_log import create_api_log
from india_banking_connector.connectors.bank_connector import BankConnector
import requests, json
from base64 import b64decode, b64encode
from frappe.utils import cstr, getdate, nowdate, flt
from india_banking_connector import utils

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
			if not self.testing:
				return frappe._dict({
					"host": "apibankingone.icicibank.com",
					"oauth_token": "",
					"make_payment" : "https://apibankingone.icicibank.com/api/v1/cibbulkpayment/bulkPayment",
					"payment_status" : "https://apibankingone.icicibank.com/api/v1/ReverseMis",
					"generate_otp" : "https://apibankingone.icicibank.com/api/Corporate/CIB/v1/Create",
					"bank_balance": "https://apibankingone.icicibank.com/api/Corporate/CIB/v1/BalanceInquiry",
					"bank_statement": "https://apibankingone.icicibank.com/api/Corporate/CIB/v1/AccountStatement",
					"bank_statement_paginated": "https://apibankingone.icicibank.com/api/Corporate/CIB/v1/AccountStatements"
				})
			else:
				frappe.throw("Connector not supported for Testing API calls.")
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
		headers =  {
			"accept": "application/json",
			"content-type": "application/json",
			"apikey": self.get_password('client_key'),
			"host": self.urls.host,
			"x-priority": self.get_priority(mode_of_transfer)
		}
		if self.bulk_transaction:
			del headers['host']; del headers['x-priority']

		return headers

	def intiate_payment(self):
		payment_details = self.payment_doc

		if self.bulk_transaction:
			payment_details = self.doc

		url = self.urls.make_payment

		headers = self.headers(payment_details.mode_of_transfer)
		payload = self.get_encrypted_payload(method= 'make_payment')

		response = requests.post(url, headers=headers, data= payload)

		log_id = create_api_log(
			response, action= "Initiate Payment",
	  		account_config = self.get_account_config("make_payment"),
			ref_doctype= payment_details.parenttype or payment_details.doctype,
			ref_docname= payment_details.parent or payment_details.name
		)

		return self.get_decrypted_response(response, method= "make_payment", log_id=log_id)

	def get_payment_status(self):
		payment_details = self.payment_doc

		if self.bulk_transaction:
			payment_details = self.doc

		url = self.urls.payment_status
		mode_of_transfer = payment_details.mode_of_transfer
		headers = self.headers(mode_of_transfer)
		payload = self.get_encrypted_payload(method= 'payment_status')

		response = requests.post(url, headers=headers, data= payload)

		log_id = create_api_log(
			response, action= "Payment Status",
	  		account_config = self.get_account_config("payment_status"),
			ref_doctype= payment_details.parenttype or payment_details.doctype,
			ref_docname= payment_details.parent or payment_details.name
		)

		return self.get_decrypted_response(response, method= "payment_status", log_id=log_id)

	def generate_otp(self):
		payment_details = self.doc
		url = self.urls.generate_otp

		headers = self.headers(payment_details.mode_of_transfer)
		payload = self.get_encrypted_payload(method= 'generate_otp')
		response = requests.post(url, headers= headers, data= payload)

		log_id = create_api_log(
			response, action= "Generate OTP",
			account_config = self.get_account_config("generate_otp"),
			ref_doctype= payment_details.parenttype or payment_details.doctype,
			ref_docname= payment_details.parent or payment_details.name
		)

		return self.get_decrypted_response(response, method= "generate_otp", log_id=log_id)

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

		if self.bulk_transaction:
			payment_details = self.doc

		encrypted_key = self.rsa_encrypt_key(self.AES_KEY, self.get_file_relative_path(connector_doc.public_key)),
		data = self.get_account_config(method)

		payment_payload = {
			"requestId": utils.get_id(10, payment_details.name),
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
		if self.bulk_transaction:
			payment_details = self.doc

		if 'A2A' in payment_details.mode_of_transfer:
			payment_details.mode_of_transfer = "Intra Bank Transfer"

		data = {}
		if method == "make_payment":
			self.set_payment_data(data, payment_details)
		elif method == "payment_status":
			self.set_payment_status_data(data, payment_details)
		elif method == "generate_otp":
			self.set_otp_data(data, payment_details)

		return data

	def set_otp_data(self, data):
		connector_doc = self
		payment_details = self.doc

		if self.bulk_transaction :
			data.update({
				'CORPID': connector_doc.corp_id,
				'USERID': connector_doc.payment_creator_user_id,
				'AGGRID': connector_doc.aggr_id,
				'AGGRNAME': connector_doc.aggr_name,
				'URN': connector_doc.urn,
				'UNIQUEID': payment_details.unique_id,
				'AMOUNT': str(payment_details.total)
			})

	def set_payment_data(self, data, payment_details):
		connector_doc = self
		if self.bulk_transaction:
			data.update({
				"FILE_DESCRIPTION": payment_details.file_reference_id,
				"CORP_ID": connector_doc.corp_id,
				"USER_ID": connector_doc.payment_creator_user_id,
				"AGGR_ID": connector_doc.aggr_id,
				"AGGR_NAME": connector_doc.aggr_name,
				"URN": connector_doc.urn,
				"UNIQUE_ID": payment_details.unique_id,
				"AGOTP": str(payment_details.otp),
				"FILE_NAME":f"{payment_details.file_reference_id}.txt",
				"FILE_CONTENT": self.construct_payment_details_content(payment_details, connector_doc)
			})
			frappe.log_error("Data - Bulk", data )
			return

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
			data.update({
				"localTxnDtTime": frappe.utils.now_datetime().strftime("%Y%m%d%H%M%S"),
				"beneAccNo": payment_details.bank_account_no,
				"beneIFSC": payment_details.branch_code,
				"amount": cstr(payment_details.amount),
				"tranRefNo": payment_details.name,
				"paymentRef": payment_details.name,
				"senderName": payment_details.company_bank_account_name,
				"mobile": payment_details.mobile_number,
				"retailerCode": connector_doc.retailer_code,
				"passCode": connector_doc.pass_code,
				"bcID": connector_doc.bcid,
				"aggrId": connector_doc.aggr_id,
				"crpId": connector_doc.corp_id,
				"crpUsr": connector_doc.corp_usr
				})

			frappe.log_error("Data - IMPS", data )
		else:
			data.update({
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
			})
			frappe.log_error("Data - NEFT", data )

	def set_payment_status_data(self, data, payment_details):
		connector_doc = self
		if self.bulk_transaction:
			payment_doc = self.doc
			data.update({
				"CORPID": connector_doc.corp_id,
				"USERID": connector_doc.payment_status_checker_user_id or connector_doc.payment_creator_user_id,
				"AGGRID": connector_doc.aggr_id,
				"URN":connector_doc.urn,
				"FILESEQNUM": payment_doc.file_sequence_number,
				"ISENCRYPTED":"N"
			})
			frappe.log_error("Data - Bulk", data )
			return

		if payment_details.mode_of_transfer == "IMPS":
			data.update({
				"transRefNo": payment_details.name,
				"date": payment_details.payment_date,
				"recon360": "N",
				"passCode": connector_doc.pass_code,
				"bcID": connector_doc.bcid
			})

		data.update({
			"AGGRID": connector_doc.aggr_id,
			"CORPID": connector_doc.corp_id,
			"USERID": connector_doc.corp_usr,
			"URN": connector_doc.urn,
			"UNIQUEID": payment_details.name
		})


	def get_decrypted_response(self, response, method, log_id= None):
		connector_doc = self
		res_dict = frappe._dict({})
		if response.ok:
			response=json.loads(response.text)
			decrypted_key= self.rsa_decrypt_key(response.get("encryptedKey"), connector_doc)
			decrypted_data = self.rsa_decrypt_data(response.get('encryptedData'), decrypted_key.encode("utf-8"))

			self.set_decrypted_response(log_id, decrypted_data)

			if self.bulk_transaction:
				return self.handle_bulk_transaction_response(response, method)

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

	def handle_bulk_transaction_response(self, response, method):
		res_dict = frappe._dict({})

		if method == "generate_otp" and response:
				if isinstance(response, str):
					response = json.loads(response)
				response= frappe._dict(response)

				if response.get('RESPONSE') == "Success":
					res_dict.status = "success"
					res_dict.message = response.get('MESSAGE')
				elif response.get('errormessage'):
					res_dict.status = "Failed"
					err_msg=None
					if response.get('ErrorCode'):
						err_msg = self.get_error_description(response.get('ErrorCode'))
					res_dict.message = err_msg or response.get('errormessage') or response.get('Message')

		elif method == "make_payment" and response:
			if isinstance(response, str):
				response =json.loads(response)

			if response.get('FILE_SEQUENCE_NUM'):
				res_dict.status="ACCEPTED"
				res_dict.message=response.get('MESSAGE_DESC')
				res_dict.file_sequence_number=response.get('FILE_SEQUENCE_NUM')
			elif response.get('errormessage') or response.get('ErrorCode'):
				res_dict.status="Failed"
				err_msg=None
				if response.get('ErrorCode'):
					err_msg = self.get_error_description(response.get('ErrorCode'))
				res_dict.message = err_msg or response.get('errormessage') or response.get('Message')

		elif method == "payment_status" and response:
			if isinstance(response, str):
				response = json.loads(response)
			response= frappe._dict(response)

			if response.get('XML',{}).get('FILE_STATUS'):
				res_dict.status = "Processed"
				res_dict.file_status = response.get('XML').get('FILE_STATUS')
				res_dict.message = self.get_file_status(response.get('XML').get('FILE_STATUS'))
				res_dict.payment_status_details = {}
				if response.get('XML').get('FILEUPLOAD_BINARY_OUTPUT').get('Records').get('Record'):
					res_dict.payment_status_details=self.format_payment_status(response.get('XML').get('FILEUPLOAD_BINARY_OUTPUT').get('Records').get('Record'))

			elif response.get('errormessage') or response.get('ErrorCode'):
				res_dict.status = "Failed"
				err_msg = None
				if response.get('ErrorCode'):
					err_msg = self.get_error_description(response.get('ErrorCode'))
				res_dict.message=err_msg or response.get('errormessage') or response.get('Message')

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

	def get_error_description(self, code):
		return {
			"108363" : "The entered date cannot be prior to the current date.",
			"108590" : "The header amount does not equal the sum of records in the uploaded file.",
			"101043" : "Type system exception occurred",
			"999481" : "Dear Customer, This facility is available for select customer segments only. For any further queries please write to corporatecare@icicibank.com",
			"108588" : "The total number of records is not same in header and file records.",
			"104668" : "Please select the proper files and attach again.",
			"110370" : "Please select the proper files and attach again.",
			"104344" : "The cut-off time for this transaction has already passed. This action cannot be performed with the current transaction date.",
			"999936" : "Transactions already processed with same unique ID, please use exclusive unique id for each transaction.",
			"111267" : "The record ID is not present in the file.",
			"110004" : "Enter the valid date as the selected date is a bank holiday.",
			"994006" : "OTP Validation Failed",
			"107889" : "OTP Validation Failed",
			"100901" : "Consumption limits not defined for the user. Transaction cannot be processed. Please contact the bank administrator",
			"104666" : "File with the same name is already uploaded"
		}.get(str(code), "Unknown Error")

	def construct_payment_details_content(self, payment_doc, connector_doc):
		content = []
		first_line = "{}|{}|{}|{}|{}|{}|{}|{}^".format("FHR",len(payment_doc.summary)+1, getdate(nowdate()).strftime('%m/%d/%Y'), payment_doc.file_reference_id,flt(payment_doc.total),"INR",connector_doc.account_number,"0011")
		content.append(first_line)
		second_line ="{}|{}|{}|{}|{}|{}|{}|{}|{}^".format("MDR",connector_doc.account_number,"0011",payment_doc.company.replace(" ","")[:30],flt(payment_doc.total),'INR', payment_doc.file_reference_id,"ICIC0000011","WIB")
		content.append(second_line)
		for payment_row in payment_doc.summary:
			if isinstance(payment_row, str):
				payment_row=json.loads(payment_row)
			payment_row = frappe._dict(payment_row)
			if (payment_doc.company_bank == payment_row.bank):
				mcw_st = "{}|{}|{}|{}|{}|{}|{}|{}|{}^".format("MCW",payment_row.bank_account_no,payment_row.bank_account_no[:4],payment_row.account_name.replace(" ","")[:30],flt(payment_row.amount),"INR",payment_row.name,payment_row.branch_code,"WIB")
				content.append(mcw_st)
			else:
				mco_st = "{}|{}|{}|{}|{}|{}|{}|{}|{}^".format("MCO", payment_row.bank_account_no,"0011",payment_row.account_name.replace(" ","")[:30],flt(payment_row.amount),"INR",payment_row.name,"NFT",payment_row.branch_code)
				content.append(mco_st)
		result = '\n'.join(content)
		byte_like = str.encode(result)
		encode_result = b64encode(byte_like).decode('utf-8')
		return encode_result

	def format_payment_status(self, records):
		if isinstance(records, str):
			records = json.loads(records)

		keys = [
			'transaction_type',
			'network_id',
			'credit_account_number',
			'debit_account_number',
			'ifsc_code',
			'currency',
			'total_amount',
			'host_reference_number',
			'host_response_code',
			'host_response_message',
			'transaction_remarks',
			'transaction_status'
		]

		result = {}
		for row in records[1:]:
			values = row.split('|')
			row_dict = dict(zip(keys, values))
			result[row_dict['transaction_remarks']]=row_dict

		return result

	def get_file_status(self, key):
		return {
			"GIP" : "This is the intermediate state where GFP batches gets executed",
			"PFI" : "(Pending for insertion)This is the state where bulk has been upload and transaction is completed from front end aand awaiting for the batch process to be completed.",
			"ENT" : "Entered state for the transaction once bulk transaction is initiated",
			"MIR" : "Manual intervention required: - goes for reversal",
			"STS" : "Success",
			"FAL" : "Failure",
			"PPD" : "Partially processed",
			"REJ" : "Transaction has gone to rejected case",
			"ATH" : "status after process scheduler batch run is completed. Its before GFP batch.",
			"CRP" : "Credit reversal pending",
			"REC" : "when initiator itself canceled or recalled the txn"
		}.get(key, "Unknown issue occured")