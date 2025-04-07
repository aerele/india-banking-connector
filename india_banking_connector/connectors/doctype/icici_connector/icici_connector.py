# Copyright (c) 2024, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

import json
import re
from base64 import b64encode

import frappe
import requests
from frappe import _
from frappe.utils import cstr, flt, getdate, now_datetime, nowdate

from india_banking_connector.connectors.bank_connector import BankConnector
from india_banking_connector.india_banking_connector.doctype.bank_request_log.bank_request_log import (
	create_api_log,
)
from india_banking_connector.utils import get_id


class ICICIConnector(BankConnector):
	bank = "ICICI Bank"

	AES_KEY = "1234567887654321".encode("utf-8")
	BLOCK_SIZE = 16
	IV = "0000000000000000".encode("utf-8")

	__all__ = ["initiate_payment", "get_payment_status"]

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		self.bulk_transaction = kwargs.get("bulk_transaction")
		self.doc = frappe._dict(kwargs.get("doc", {}))
		self.payment_doc = frappe._dict(kwargs.get("payment_doc", {}))

	@property
	def urls(self):
		return super().urls

	def headers(self, mode_of_transfer=None, params=None):
		headers = {
			"accept": "*/*",
			"content-type": "application/json",
			"apikey": self.get_password("client_key"),
		}
		if self.bulk_transaction:
			if params:
				headers.update(**params)
			headers.update(
				{
					"host": self.urls.host,
					"x-priority": self.get_priority(mode_of_transfer),
				}
			)

		return headers

	def initiate_payment(self):
		payment_details = self.payment_doc if not self.bulk_transaction else self.doc
		unique_id = "".join(re.findall(r"[0-9a-zA-Z]", payment_details.name))[-10:]
		if not self.bulk_transaction:
			unique_id = payment_details.name

		if existing_payment_response := self.validate_duplicate_payments(
			unique_id=unique_id
		):
			return existing_payment_response

		url = self.urls.make_payment
		headers = self.headers(payment_details.mode_of_transfer)
		payload = self.get_encrypted_payload(method="make_payment")

		response = requests.post(url, headers=headers, data=payload)

		log_id = create_api_log(
			response,
			action="Initiate Payment",
			account_config=self.get_account_config("make_payment"),
			ref_doctype=payment_details.parenttype or payment_details.doctype,
			ref_docname=payment_details.parent or payment_details.name,
			unique_id=unique_id,
		)

		return self.get_decrypted_response(
			response, method="make_payment", log_id=log_id
		)

	def get_payment_status(self):
		payment_details = self.payment_doc if not self.bulk_transaction else self.doc
		unique_id = "".join(re.findall(r"[0-9a-zA-Z]", payment_details.name))[-10:]
		if not self.bulk_transaction:
			unique_id = payment_details.name

		mode_of_transfer = payment_details.mode_of_transfer

		url = self.urls.payment_status
		headers = self.headers(mode_of_transfer)
		payload = self.get_encrypted_payload(method="payment_status")

		response = requests.post(url, headers=headers, data=payload)

		log_id = create_api_log(
			response,
			action="Payment Status",
			account_config=self.get_account_config("payment_status"),
			ref_doctype=payment_details.parenttype or payment_details.doctype,
			ref_docname=payment_details.parent or payment_details.name,
			unique_id=unique_id,
		)

		return self.get_decrypted_response(
			response, method="payment_status", log_id=log_id
		)

	def generate_otp(self):
		payment_details = self.payment_doc if not self.bulk_transaction else self.doc

		url = self.urls.generate_otp
		headers = self.headers(payment_details.mode_of_transfer)
		payload = self.get_encrypted_payload(method="generate_otp")

		response = requests.post(url, headers=headers, data=payload)

		log_id = create_api_log(
			response,
			action="Generate OTP",
			account_config=self.get_account_config("generate_otp"),
			ref_doctype=payment_details.parenttype or payment_details.doctype,
			ref_docname=payment_details.parent or payment_details.name,
		)

		return self.get_decrypted_response(
			response, method="generate_otp", log_id=log_id
		)

	def get_priority(self, mode_of_transfer):
		return {"RTGS": "0001", "IMPS": "0100"}.get(mode_of_transfer, "0010")

	def get_encrypted_payload(self, method):
		connector_doc = self

		payment_details = self.payment_doc if not self.bulk_transaction else self.doc

		data = self.get_account_config(method)

		if method in ["make_payment", "payment_status", "generate_otp"]:
			encrypted_key = self.rsa_encrypt_key(
				self.AES_KEY, self.get_file_relative_path(connector_doc.public_key)
			)

			return json.dumps(
				{
					"requestId": get_id(10, payment_details.name),
					"service": "",
					"oaepHashingAlgorithm": "NONE",
					"encryptedKey": encrypted_key,
					"encryptedData": self.aes_encrypt_data(data, self.AES_KEY),
					"clientInfo": "",
					"optionalParam": "",
					"iv": b64encode(self.IV).decode("utf-8"),
				}
			)
		else:
			public_key_path = self.get_file_relative_path(connector_doc.public_key)
			return self.rsa_encrypt_data(data, public_key_path)

	def get_account_config(self, method):
		payment_details = self.payment_doc if not self.bulk_transaction else self.doc

		if "A2A" in payment_details.get("mode_of_transfer", ""):
			payment_details.mode_of_transfer = "Intra Bank Transfer"

		data = {}
		method_map = {
			"generate_otp": self.set_otp_data,
			"make_payment": self.set_payment_data,
			"payment_status": self.set_payment_status_data,
			"bank_balance": self.set_balance_data,
			"bank_statement": self.set_statement_data,
		}

		if method in method_map:
			method_map[method](data)

		return data

	def set_statement_data(self, data):
		connector_doc = self
		payload_details = self.doc

		from_date = getdate(payload_details.get("from_date", "")).strftime("%d-%m-%Y")
		to_date = getdate(payload_details.get("to_date", "")).strftime("%d-%m-%Y")

		data.update(
			{
				"AGGRID": connector_doc.aggr_id,
				"CORPID": connector_doc.corp_id,
				"USERID": connector_doc.corp_usr,
				"URN": connector_doc.urn,
				"FROMDATE": from_date,
				"TODATE": to_date,
				"ACCOUNTNO": connector_doc.account_number,
			}
		)
		if payload_details.get("paginated"):
			data.update({"CONFLG": "N"})
		if payload_details.get("last_transaction_id"):
			data.update(
				{"CONFLG": "Y", "LASTTRID": payload_details.get("last_transaction_id")}
			)

	def set_balance_data(self, data):
		connector_doc = self

		data.update(
			{
				"AGGRID": connector_doc.aggr_id,
				"CORPID": connector_doc.corp_id,
				"USERID": connector_doc.corp_usr,
				"URN": connector_doc.urn,
				"ACCOUNTNO": connector_doc.account_number,
			}
		)

	def set_otp_data(self, data):
		connector_doc = self
		payment_details = self.payment_doc if not self.bulk_transaction else self.doc

		unique_id = "".join(re.findall(r"[0-9a-zA-Z]", payment_details.name))[-10:]

		if self.bulk_transaction:
			data.update(
				{
					"CORPID": connector_doc.corp_id,
					"USERID": connector_doc.corp_usr,
					"AGGRID": connector_doc.aggr_id,
					"AGGRNAME": connector_doc.aggr_name,
					"URN": connector_doc.urn,
					"UNIQUEID": unique_id,
					"AMOUNT": str(payment_details.total),
				}
			)

	def set_payment_data(self, data):
		connector_doc = self
		payment_details = self.payment_doc if not self.bulk_transaction else self.doc
		file_reference_id = "".join(re.findall(r"[0-9a-zA-Z]", payment_details.name))[
			-10:
		]

		unique_id = "".join(re.findall(r"[0-9a-zA-Z]", payment_details.name))[-10:]

		if self.bulk_transaction:
			data.update(
				{
					"FILE_DESCRIPTION": file_reference_id,
					"CORP_ID": connector_doc.corp_id,
					"USER_ID": connector_doc.corp_usr,
					"AGGR_ID": connector_doc.aggr_id,
					"AGGR_NAME": connector_doc.aggr_name,
					"URN": connector_doc.urn,
					"UNIQUE_ID": unique_id,
					"AGOTP": str(payment_details.otp),
					"FILE_NAME": f"{file_reference_id}.txt",
					"FILE_CONTENT": self.construct_payment_details_content(
						payment_details, connector_doc
					),
				}
			)
			return

		if payment_details.mode_of_transfer == "IMPS":
			if not connector_doc.enable_imps:
				frappe.throw(
					_(
						"IMPS is not enabled for this {} account.".format(
							connector_doc.account_number
						)
					)
				)

			data.update(
				{
					"localTxnDtTime": now_datetime().strftime("%Y%m%d%H%M%S"),
					"beneAccNo": payment_details.bank_account_no,
					"beneIFSC": connector_doc.ifsc_code
					if payment_details.bank == "ICICI Bank"
					else payment_details.branch_code,
					"amount": cstr(payment_details.amount),
					"tranRefNo": payment_details.name,
					"paymentRef": payment_details.name,
					"senderName": payment_details.company_bank_account_name,
					"mobile": payment_details.mobile_number,
					"retailerCode": connector_doc.retailer_code or "rcode",
					"passCode": connector_doc.pass_code,
					"bcID": connector_doc.bcid,
					"aggrId": connector_doc.aggr_id,
					"crpId": connector_doc.corp_id,
					"crpUsr": connector_doc.corp_usr,
				}
			)

		elif payment_details.mode_of_transfer == "RTGS":
			data.update(
				{
					"AGGRID": connector_doc.aggr_id,
					"CORPID": connector_doc.corp_id,
					"USERID": connector_doc.corp_usr,
					"URN": connector_doc.urn,
					"AGGRNAME": connector_doc.aggr_name,
					"UNIQUEID": payment_details.name,
					"DEBITACC": connector_doc.account_number,
					"CREDITACC": payment_details.bank_account_no,
					"IFSC": connector_doc.ifsc_code
					if payment_details.bank == "ICICI Bank"
					else payment_details.branch_code,
					"AMOUNT": cstr(payment_details.amount),
					"CURRENCY": "INR",
					"TXNTYPE": "TPA" if payment_details.bank == "ICICI Bank" else "RTG",
					"PAYEENAME": payment_details.account_name,
					"REMARKS": f"{payment_details.party_type} - {payment_details.party}",
					"WORKFLOW_REQD": connector_doc.get("workflow_required", "Y"),
					"BENLEI": payment_details.get("lei_number", ""),
				}
			)

		else:
			data.update(
				{
					"tranRefNo": payment_details.name,
					"amount": cstr(payment_details.amount),
					"senderAcctNo": connector_doc.account_number,
					"beneAccNo": payment_details.bank_account_no,
					"beneName": payment_details.account_name,
					"beneIFSC": connector_doc.ifsc_code or "ICIC0000103"
					if payment_details.bank == "ICICI Bank"
					else payment_details.branch_code,
					"narration1": payment_details.party_name,
					"narration2": connector_doc.aggr_id,
					"crpId": connector_doc.corp_id,
					"crpUsr": connector_doc.corp_usr,
					"aggrId": connector_doc.aggr_id,
					"urn": connector_doc.urn,
					"aggrName": connector_doc.aggr_name,
					"txnType": "TPA" if payment_details.bank == "ICICI Bank" else "RGS",
					"WORKFLOW_REQD": connector_doc.get("workflow_required", "Y"),
					"BENLEI": payment_details.get("lei_number", ""),
				}
			)

	def set_payment_status_data(self, data):
		connector_doc = self
		payment_details = self.payment_doc if not self.bulk_transaction else self.doc
		unique_id = "".join(re.findall(r"[0-9a-zA-Z]", payment_details.name))[-10:]

		if self.bulk_transaction:
			payment_doc = self.doc
			data.update(
				{
					"CORPID": connector_doc.corp_id,
					"USERID": connector_doc.status_corp_usr,
					"AGGRID": connector_doc.aggr_id,
					"URN": connector_doc.urn,
					"UNIQUEID": unique_id,
					"FILESEQNUM": payment_doc.file_sequence_number,
					"ISENCRYPTED": "N",
				}
			)
			return

		if payment_details.mode_of_transfer == "IMPS":
			data.update(
				{
					"transRefNo": payment_details.name,
					"date": payment_details.payment_date,
					"recon360": "N",
					"passCode": connector_doc.pass_code,
					"bcID": connector_doc.bcid,
				}
			)

		data.update(
			{
				"AGGRID": connector_doc.aggr_id,
				"CORPID": connector_doc.corp_id,
				"USERID": connector_doc.corp_usr,
				"URN": connector_doc.urn,
				"UNIQUEID": payment_details.name,
			}
		)

	def get_decrypted_response(self, response, method, log_id=None):
		connector_doc = self
		res_dict = frappe._dict({})
		if response.ok:
			response = json.loads(response.text)
			if method in ["make_payment", "payment_status", "generate_otp"]:
				decrypted_key = self.rsa_decrypt_key(
					response.get("encryptedKey"),
					self.get_file_relative_path(connector_doc.private_key),
				)
				decrypted_data = self.aes_decrypt_data(
					response.get("encryptedData"), decrypted_key
				)

			else:
				decrypted_key = self.rsa_decrypt_key(
					response.get("encryptedKey"),
					self.get_file_relative_path(connector_doc.private_key),
				)
				decrypted_data = self.rsa_decrypt_data(
					response.get("encryptedData"), decrypted_key
				)

			self.set_decrypted_response(log_id, decrypted_data)

			self.get_formated_response(decrypted_data, res_dict, method)
		else:
			res_dict.status = "Request Failure"
			res_dict.message = response.text or response.status_code

		return res_dict

	def get_formated_response(self, data, res_dict, method):
		if isinstance(data, str):
			data = json.loads(data)

		data = frappe._dict(data)

		if self.bulk_transaction:
			self.handle_bulk_transaction_response(data, res_dict, method)
			return res_dict

		if method == "make_payment" and data:
			if data.STATUS in ["SUCCESS", "PENDING", "PENDING FOR PROCESSING"]:
				res_dict.payment_status = "ACCEPTED"
				res_dict.message = f"Payment {data.get('STATUS', '').title()}"
				res_dict.summary_details = {
					self.payment_doc.name: {"payment_status": "Accepted"}
				}
			elif data.UTRNUMBER:
				res_dict.status = "ACCEPTED"
				res_dict.message = data.UTRNUMBER
				res_dict.summary_details = {
					self.payment_doc.name: {"payment_status": "Accepted"}
				}
			elif data.STATUS == "DUPLICATE":
				res_dict.payment_status = "ACCEPTED"
				res_dict.message = f"Payment {data.get('STATUS', '').title()}"
				res_dict.summary_details = {
					self.payment_doc.name: {"payment_status": "Failed"}
				}
			elif data.errorCode == "997":
				res_dict.payment_status = "Request Failure"
				res_dict.message = f"{data.errorCode} : {data.description}"
			else:
				res_dict.payment_status = "FAILED"
				res_dict.message = f"Invalid Status : {data.STATUS}"

		elif method == "payment_status" and data:
			if data.STATUS == "SUCCESS":
				res_dict.payment_status = "PROCESSED"
				res_dict.summary_details = {
					self.payment_doc.name: {
						"status": "Processed",
						"utr_number": data.UTRNUMBER,
						"message": data.MESSAGE or "Payment Completed",
					}
				}
			elif data.STATUS == "PENDING":
				res_dict.payment_status = "PROCESSED"
				res_dict.summary_details = {
					self.payment_doc.name: {
						"status": "Pending",
						"message": data.MESSAGE or "Payment Pending",
					}
				}
			elif data.STATUS == "FAILURE":
				res_dict.payment_status = "PROCESSED"
				res_dict.summary_details = {
					self.payment_doc.name: {
						"status": "Failed",
						"message": data.MESSAGE or "Payment Failed",
					}
				}
			else:
				res_dict.payment_status = "PROCESSED"
				res_dict.summary_details = {
					self.payment_doc.name: {
						"status": "Request Failure",
						"message": data.MESSAGE or "Payment Request Failure",
					}
				}

	def get_summary_details(self, status):
		summary_details = {}

		for summary in self.doc.summary:
			summary_details.update({summary.get("name"): {"payment_status": status}})

		return summary_details

	def handle_bulk_transaction_response(self, data, res_dict, method):
		if method == "generate_otp" and data:
			if data.get("RESPONSE") == "Success":
				res_dict.status = "success"
				res_dict.message = data.get("MESSAGE")

			elif data.get("errormessage"):
				res_dict.status = "Failed"
				err_msg = None

				if data.get("ErrorCode"):
					err_msg = self.get_error_description(data.get("ErrorCode"))

				res_dict.message = (
					err_msg or data.get("errormessage") or data.get("Message")
				)

		elif method == "make_payment" and data:
			if data.get("FILE_SEQUENCE_NUM"):
				res_dict.payment_status = "ACCEPTED"
				res_dict.message = data.get("MESSAGE_DESC")
				res_dict.file_sequence_number = data.get("FILE_SEQUENCE_NUM")

				res_dict.summary_details = self.get_summary_details("Accepted")

			elif data.get("errormessage") or data.get("ErrorCode"):
				res_dict.payment_status = "ACCEPTED"
				err_msg = ""

				if data.get("ErrorCode"):
					err_msg = self.get_error_description(data.get("ErrorCode"))
				res_dict.message = (
					err_msg or data.get("errormessage") or data.get("Message")
				)

				res_dict.summary_details = self.get_summary_details("Failed")

		elif method == "payment_status" and data:
			if file_status := data.get("XML", {}).get("FILE_STATUS"):
				res_dict.payment_status = "PROCESSED"
				if file_status in ["REJ", "REC"]:
					res_dict.message = "Payment Rejected"
				elif file_status in ["FAL"]:
					res_dict.message = "Payment Failed"

				res_dict.summary_details = {}

				if (
					data.get("XML")
					.get("FILEUPLOAD_BINARY_OUTPUT")
					.get("Records")
					.get("Record")
				):
					res_dict.summary_details = self.format_payment_status(
						data.get("XML", {})
						.get("FILEUPLOAD_BINARY_OUTPUT", {})
						.get("Records", {})
						.get("Record", "")
					)

			elif data.get("errormessage") or data.get("ErrorCode"):
				res_dict.status = "Failed"
				err_msg = None
				if data.get("ErrorCode"):
					err_msg = self.get_error_description(data.get("ErrorCode"))

				res_dict.message = (
					err_msg or data.get("errormessage") or data.get("Message")
				)

		elif method == "bank_balance" and data:
			if data.get("RESPONSE") == "SUCCESS":
				res_dict.server_status = "Success"
				res_dict.balance = data.get("EFFECTIVEBAL", 0)
				res_dict.date = data.get("DATE", "")
			else:
				res_dict.server_status = "Failed"
				res_dict.message = data

		elif method == "bank_statement" and data:
			records = data.get("Record", [])
			transactions = []

			if data.get("RESPONSE") == "SUCCESS":
				for txn in records:
					transaction = {
						"transaction_date": txn.get("TXNDATE", ""),
						"transaction_amount": txn.get("AMOUNT"),
						"reference_number": txn.get("TRANSACTIONID")
						or txn.get("CHEQUENO"),
					}
					transactions.append(transaction)

			res_dict.server_status = "Success"
			res_dict.bank_statements = transactions
			res_dict.last_transaction_id = data.get("LISTTRID")

		return res_dict

	def set_decrypted_response(self, log_id, response_data):
		if isinstance(response_data, str):
			response_data = json.loads(response_data)

		response_data = json.dumps(response_data, indent=4)

		if frappe.db.exists("Bank Request Log", log_id):
			frappe.db.set_value(
				"Bank Request Log", log_id, "decrypted_response", response_data
			)

	def get_cert(self):
		return (
			self.get_file_relative_path(self.cert_file),
			self.get_file_relative_path(self.private_key),
		)

	def get_transaction_history(self):
		return "Transaction History Not Implemented"

	def get_bank_balance(self):
		url = self.urls.bank_balance
		headers = self.headers(params={"content-type": "text/plain"})
		payload = self.get_encrypted_payload(method="bank_balance")

		response = requests.post(url, headers=headers, data=payload)

		log_id = create_api_log(
			response,
			action="Bank Balance",
			account_config=self.get_account_config("bank_balance"),
			ref_doctype="Bank Balance",
			ref_docname=self.account_number,
		)

		return self.get_decrypted_response(
			response, method="bank_balance", log_id=log_id
		)

	def get_bank_statement(self):
		url = self.urls.bank_statement
		headers = self.headers(params={"content-type": "text/plain"})
		payload = self.get_encrypted_payload(method="bank_statement")

		response = requests.post(url, headers=headers, data=payload)

		log_id = create_api_log(
			response,
			action="Bank Statement",
			account_config=self.get_account_config("bank_statement"),
			ref_doctype="Bank Statement",
			ref_docname=self.account_number,
		)

		return self.get_decrypted_response(
			response, method="bank_statement", log_id=log_id
		)

	def get_error_description(self, code):
		return {
			"108363": "The entered date cannot be prior to the current date.",
			"108590": "The header amount does not equal the sum of records in the uploaded file.",
			"101043": "Type system exception occurred",
			"999481": "Dear Customer, This facility is available for select customer segments only. For any further queries please write to corporatecare@icicibank.com",
			"108588": "The total number of records is not same in header and file records.",
			"104668": "Please select the proper files and attach again.",
			"110370": "Please select the proper files and attach again.",
			"104344": "The cut-off time for this transaction has already passed. This action cannot be performed with the current transaction date.",
			"999936": "Transactions already processed with same unique ID, please use exclusive unique id for each transaction.",
			"111267": "The record ID is not present in the file.",
			"110004": "Enter the valid date as the selected date is a bank holiday.",
			"994006": "OTP Validation Failed",
			"107889": "OTP Validation Failed",
			"100901": "Consumption limits not defined for the user. Transaction cannot be processed. Please contact the bank administrator",
			"104666": "File with the same name is already uploaded",
		}.get(str(code), "Unknown Error")

	def construct_payment_details_content(self, payment_doc, connector_doc):
		file_reference_id = "".join(re.findall(r"[0-9a-zA-Z]", payment_doc.name))[-10:]

		content = []
		first_line = "{}|{}|{}|{}|{}|{}|{}|{}^".format(
			"FHR",
			len(payment_doc.summary) + 1,
			getdate(nowdate()).strftime("%m/%d/%Y"),
			file_reference_id,
			flt(payment_doc.total),
			"INR",
			connector_doc.account_number,
			"0011",
		)
		content.append(first_line)
		second_line = "{}|{}|{}|{}|{}|{}|{}|{}|{}^".format(
			"MDR",
			connector_doc.account_number,
			"0011",
			payment_doc.company.replace(" ", "")[:30],
			flt(payment_doc.total),
			"INR",
			file_reference_id,
			"ICIC0000011",
			"WIB",
		)
		content.append(second_line)
		for payment_row in payment_doc.summary:
			if isinstance(payment_row, str):
				payment_row = json.loads(payment_row)
			payment_row = frappe._dict(payment_row)
			if payment_doc.company_bank == payment_row.bank:
				mcw_st = "{}|{}|{}|{}|{}|{}|{}|{}|{}^".format(
					"MCW",
					payment_row.bank_account_no,
					payment_row.bank_account_no[:4],
					payment_row.account_name.replace(" ", "")[:30],
					flt(payment_row.amount),
					"INR",
					payment_row.name,
					payment_row.branch_code,
					"WIB",
				)
				content.append(mcw_st)
			else:
				mco_st = "{}|{}|{}|{}|{}|{}|{}|{}|{}^".format(
					"MCO",
					payment_row.bank_account_no,
					"0011",
					payment_row.account_name.replace(" ", "")[:30],
					flt(payment_row.amount),
					"INR",
					payment_row.name,
					"NFT",
					payment_row.branch_code,
				)
				content.append(mco_st)
		result = "\n".join(content)
		byte_like = str.encode(result)
		encode_result = b64encode(byte_like).decode("utf-8")
		return encode_result

	def format_payment_status(self, records):
		if isinstance(records, str):
			records = json.loads(records)

		keys = [
			"transaction_type",
			"network_id",
			"credit_account_number",
			"debit_account_number",
			"ifsc_code",
			"currency",
			"total_amount",
			"host_reference_number",
			"host_response_code",
			"host_response_message",
			"transaction_remarks",
			"transaction_status",
		]

		result = {}
		for row in records[1:]:
			values = row.split("|")
			row_dict = dict(zip(keys, values))
			if row_dict.get("transaction_status", "") == "SUC":
				result.update(
					{
						row_dict.get("transaction_remarks"): {
							"status": "Processed",
							"utr_number": row_dict.get("host_reference_number", ""),
							"message": row_dict.get(
								"host_response_message", "Payment Accepted"
							),
						}
					}
				)
			if row_dict.get("transaction_status", "") == "FAL":
				result.update(
					{
						row_dict.get("transaction_remarks"): {
							"status": "Failed",
							"message": row_dict.get(
								"host_response_message", "Payment Failed"
							),
						}
					}
				)
			if row_dict.get("transaction_status", "") in ["REJ", "REC"]:
				result.update(
					{
						row_dict.get("transaction_remarks"): {
							"status": "Rejected",
							"message": row_dict.get(
								"host_response_message", "Payment Rejected"
							),
						}
					}
				)

		return result

	def get_file_status(self, key):
		return {
			"GIP": "This is the intermediate state where GFP batches gets executed",
			"PFI": "(Pending for insertion)This is the state where bulk has been upload and transaction is completed from front end aand awaiting for the batch process to be completed.",
			"ENT": "Entered state for the transaction once bulk transaction is initiated",
			"MIR": "Manual intervention required: - goes for reversal",
			"STS": "Success",
			"FAL": "Failure",
			"PPD": "Partially processed",
			"REJ": "Transaction has gone to rejected case",
			"ATH": "status after process scheduler batch run is completed. Its before GFP batch.",
			"CRP": "Credit reversal pending",
			"REC": "when initiator itself canceled or recalled the txn",
		}.get(key, "Unknown issue occured")
