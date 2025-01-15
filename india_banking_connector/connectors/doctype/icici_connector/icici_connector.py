# Copyright (c) 2024, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

import json
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
import re


class ICICIConnector(BankConnector):
	bank = "ICICI Bank"

	AES_KEY = "1234567887654321".encode("utf-8")
	BLOCK_SIZE = 16
	IV = "0000000000000000".encode("utf-8")

	__all__ = ["intiate_payment", "get_payment_status"]

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		self.bulk_transaction = kwargs.get("bulk_transaction")
		self.doc = frappe._dict(kwargs.get("doc", {}))
		self.payment_doc = frappe._dict(kwargs.get("payment_doc", {}))

	@property
	def urls(self):
		host = (
			"apibankingonesandbox.icicibank.com"
			if self.testing
			else "apibankingone.icicibank.com"
		)

		if self.bulk_transaction and self.testing:
			frappe.throw("Connector not supported for Testing API calls.")

		urls = {
			"host": host,
			"make_payment": f"https://{host}/api/v1/composite-payment",
			"payment_status": f"https://{host}/api/v1/composite-status",
		}

		if self.bulk_transaction:
			urls.update(
				{
					"generate_otp": f"https://{host}/api/Corporate/CIB/v1/Create",
					"bank_balance": f"https://{host}/api/Corporate/CIB/v1/BalanceInquiry",
					"bank_statement": f"https://{host}/api/Corporate/CIB/v1/AccountStatement",
					"bank_statement_paginated": f"https://{host}/api/Corporate/CIB/v1/AccountStatements",
				}
			)

		return frappe._dict(urls)

	def headers(self, mode_of_transfer=None):
		headers = {
			"accept": "*/*",
			"content-type": "application/json",
			"apikey": self.get_password("client_key"),
		}
		if not self.bulk_transaction:
			headers.update(
				{
					"host": self.urls.host,
					"x-priority": self.get_priority(mode_of_transfer),
				}
			)

		return headers

	def intiate_payment(self):
		payment_details = self.payment_doc if not self.bulk_transaction else self.doc

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
		)

		return self.get_decrypted_response(
			response, method="make_payment", log_id=log_id
		)

	def get_payment_status(self):
		payment_details = self.payment_doc if not self.bulk_transaction else self.doc

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

		encrypted_key = self.rsa_encrypt_key(
			self.AES_KEY, self.get_file_relative_path(connector_doc.public_key)
		)
		data = self.get_account_config(method)

		return json.dumps(
			{
				"requestId": get_id(10, payment_details.name),
				"service": "",
				"oaepHashingAlgorithm": "NONE",
				"encryptedKey": encrypted_key,
				"encryptedData": self.rsa_encrypt_data(data, self.AES_KEY),
				"clientInfo": "",
				"optionalParam": "",
				"iv": b64encode(self.IV).decode("utf-8"),
			}
		)

	def get_account_config(self, method):
		payment_details = self.payment_doc if not self.bulk_transaction else self.doc

		if "A2A" in payment_details.mode_of_transfer:
			payment_details.mode_of_transfer = "Intra Bank Transfer"

		data = {}
		method_map = {
			"make_payment": self.set_payment_data,
			"payment_status": self.set_payment_status_data,
			"generate_otp": self.set_otp_data,
		}

		if method in method_map:
			method_map[method](data)

		return data

	def set_otp_data(self, data):
		connector_doc = self
		payment_details = self.payment_doc if not self.bulk_transaction else self.doc

		unique_id = "".join(re.findall(r"[0-9a-zA-Z]", self.name))[-10:]

		if self.bulk_transaction:
			data.update(
				{
					"CORPID": connector_doc.corp_id,
					"USERID": connector_doc.payment_creator_user_id,
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
		file_reference_id = "".join(re.findall(r"[0-9a-zA-Z]", self.name))[-10:]

		unique_id = "".join(re.findall(r"[0-9a-zA-Z]", self.name))[-10:]

		if self.bulk_transaction:
			data.update(
				{
					"FILE_DESCRIPTION": file_reference_id,
					"CORP_ID": connector_doc.corp_id,
					"USER_ID": connector_doc.payment_creator_user_id,
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
					"retailerCode": connector_doc.retailer_code,
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
					"WORKFLOW_REQD": "N",
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
					"beneIFSC": connector_doc.ifsc_code
					if payment_details.bank == "ICICI Bank"
					else payment_details.branch_code,
					"narration1": payment_details.party_name,
					"narration2": connector_doc.aggr_id,
					"crpId": connector_doc.corp_id,
					"crpUsr": connector_doc.corp_usr,
					"aggrId": connector_doc.aggr_id,
					"urn": connector_doc.urn,
					"aggrName": connector_doc.aggr_name,
					"txnType": "TPA" if payment_details.bank == "ICICI Bank" else "RTG",
					"WORKFLOW_REQD": "N",
				}
			)

	def set_payment_status_data(self, data):
		connector_doc = self
		payment_details = self.payment_doc if not self.bulk_transaction else self.doc

		if self.bulk_transaction:
			payment_doc = self.doc
			data.update(
				{
					"CORPID": connector_doc.corp_id,
					"USERID": connector_doc.payment_status_checker_user_id
					or connector_doc.payment_creator_user_id,
					"AGGRID": connector_doc.aggr_id,
					"URN": connector_doc.urn,
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

			decrypted_key = self.rsa_decrypt_key(
				response.get("encryptedKey"),
				self.get_file_relative_path(connector_doc.private_key),
			)
			decrypted_data = self.rsa_decrypt_data(
				response.get("encryptedData"), decrypted_key
			)

			self.set_decrypted_response(log_id, decrypted_data)

			if self.bulk_transaction:
				return self.handle_bulk_transaction_response(response, method)

			parsed_data = (
				json.loads(decrypted_data)
				if isinstance(decrypted_data, str)
				else decrypted_data
			)

			if method == "make_payment" and parsed_data:
				response = frappe._dict(parsed_data)
				status_map = {
					"SUCCESS": "ACCEPTED",
					"PENDING": "ACCEPTED",
					"DUPLICATE": "FAILURE",
				}

				res_dict.status = status_map.get(response.STATUS, "Request Failure")
				res_dict.message = response.MESSAGE

				if response.errorCode == "997":
					res_dict.status = "Request Failure"
					res_dict.message = f"{response.errorCode} : {response.description}"

			elif method == "payment_status" and parsed_data:
				response = frappe._dict(parsed_data)

				status_map = {
					"SUCCESS": ("Processed", "Success"),
					"PENDING": ("Pending", response.MESSAGE),
					"FAILURE": ("FAILURE", response.MESSAGE),
				}

				res_dict.status, res_dict.message = status_map.get(
					response.STATUS, ("Request Failure", response.MESSAGE)
				)
				if response.STATUS == "SUCCESS":
					res_dict.reference_number = response.UTRNUMBER

		else:
			res_dict.status = "Request Failure"
			res_dict.message = response.text or response.status_code

		return res_dict

	def handle_bulk_transaction_response(self, response, method):
		res_dict = frappe._dict({})

		if isinstance(response, str):
			response = json.loads(response)

		response = frappe._dict(response)

		if method == "generate_otp" and response:
			if response.get("RESPONSE") == "Success":
				res_dict.status = "success"
				res_dict.message = response.get("MESSAGE")

			elif response.get("errormessage"):
				res_dict.status = "Failed"
				err_msg = None

				if response.get("ErrorCode"):
					err_msg = self.get_error_description(response.get("ErrorCode"))

				res_dict.message = (
					err_msg or response.get("errormessage") or response.get("Message")
				)

		elif method == "make_payment" and response:
			if response.get("FILE_SEQUENCE_NUM"):
				res_dict.status = "ACCEPTED"
				res_dict.message = response.get("MESSAGE_DESC")
				res_dict.file_sequence_number = response.get("FILE_SEQUENCE_NUM")

			elif response.get("errormessage") or response.get("ErrorCode"):
				res_dict.status = "Failed"
				err_msg = None

				if response.get("ErrorCode"):
					err_msg = self.get_error_description(response.get("ErrorCode"))
				res_dict.message = (
					err_msg or response.get("errormessage") or response.get("Message")
				)

		elif method == "payment_status" and response:
			if response.get("XML", {}).get("FILE_STATUS"):
				res_dict.status = "Processed"
				res_dict.file_status = response.get("XML").get("FILE_STATUS")
				res_dict.message = self.get_file_status(
					response.get("XML").get("FILE_STATUS")
				)
				res_dict.payment_status_details = {}

				if (
					response.get("XML")
					.get("FILEUPLOAD_BINARY_OUTPUT")
					.get("Records")
					.get("Record")
				):
					res_dict.payment_status_details = self.format_payment_status(
						response.get("XML")
						.get("FILEUPLOAD_BINARY_OUTPUT")
						.get("Records")
						.get("Record")
					)

			elif response.get("errormessage") or response.get("ErrorCode"):
				res_dict.status = "Failed"
				err_msg = None
				if response.get("ErrorCode"):
					err_msg = self.get_error_description(response.get("ErrorCode"))

				res_dict.message = (
					err_msg or response.get("errormessage") or response.get("Message")
				)

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

	def get_balance(self):
		return "Balance Not Implemented"

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
		file_reference_id = "".join(re.findall(r"[0-9a-zA-Z]", self.name))[-10:]

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
			result[row_dict["transaction_remarks"]] = row_dict

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
