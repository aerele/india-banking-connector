# Copyright (c) 2025, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

import hashlib
import json

import frappe
import requests
from frappe import _
from frappe.query_builder import DocType
from frappe.utils import cstr, flt, get_datetime, getdate

from india_banking_connector.connectors.bank_connector import BankConnector
from india_banking_connector.india_banking_connector.doctype.bank_request_log.bank_request_log import (
	create_api_log,
)


class BankofBarodaConnector(BankConnector):
	__all__ = [
		"initiate_payment",
		"get_payment_status",
		"get_bank_balance",
		"get_bank_statement",
	]

	status_key_map = {
		"make_payment": "paymentTxnResp",
		"payment_status": "paymentsTxnInqResp",
		"bank_balance": "accBalResp",
		"bank_statement": "accountStmtResp",
	}

	def __init__(self, *args, **kwargs):
		self.bank = "Bank of Baroda"
		super().__init__(*args, **kwargs)

		self.bulk_transaction = kwargs.get("bulk_transaction")
		self.doc = frappe._dict(kwargs.get("doc", {}))
		self.payment_doc = frappe._dict(kwargs.get("payment_doc", {}))

		self.account_config = {}

	def update_aes_and_iv(self):
		if self.encrypted:
			self.client_code = self.encrypted_client_code
			self.account_number = self.encrypted_account_number

		self.AES_KEY = self.get_password("aes_key").encode("utf-8")
		self.IV = self.get_password("iv").encode("utf-8")

	@property
	def urls(self):
		self.update_aes_and_iv()

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

	def headers(self):
		return {
			"Content-Type": "application/json",
			"ClientCode": self.client_code,
		}

	def initiate_payment(self):
		payment_details = self.payment_doc
		unique_id = payment_details.name

		if existing_payment_response := self.validate_duplicate_payments(
			unique_id=unique_id
		):
			return existing_payment_response

		url = self.urls.make_payment
		headers = self.headers()
		encrypted_payload, checksum = self.get_encrypted_payload(method="make_payment")
		payload = {
			"paymentTxnReq": encrypted_payload,
		}
		if checksum:
			payload["checksum"] = checksum

		response = requests.post(url, headers=headers, data=json.dumps(payload))

		log_id = create_api_log(
			response,
			action="Initiate Payment",
			account_config=self.account_config,
			ref_doctype=payment_details.parenttype,
			ref_docname=payment_details.parent,
			unique_id=unique_id,
		)

		return self.get_decrypted_response(
			response, method="make_payment", log_id=log_id
		)

	def get_payment_status(self):
		payment_details = self.payment_doc
		unique_id = payment_details.name

		url = self.urls.payment_status
		headers = self.headers()

		encrypted_payload, checksum = self.get_encrypted_payload(
			method="payment_status"
		)
		payload = {
			"paymentsTxnInqReq": encrypted_payload,
		}
		if checksum:
			payload["checksum"] = checksum

		response = requests.post(url, headers=headers, data=json.dumps(payload))

		log_id = create_api_log(
			response,
			action="Payment Status",
			account_config=self.account_config,
			ref_doctype=payment_details.parenttype,
			ref_docname=payment_details.parent,
			unique_id=unique_id,
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

		encrypted_payload, checksum = self.get_encrypted_payload(method="bank_balance")
		payload = {
			"accBalReq": encrypted_payload,
		}
		if checksum:
			payload["checksum"] = checksum

		response = requests.post(url, headers=headers, data=json.dumps(payload))

		log_id = create_api_log(
			response,
			action="Bank Balance",
			account_config=self.account_config,
			ref_doctype=self.doctype,
			ref_docname=self.name,
			unique_id=unique_id,
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

		encrypted_payload, checksum = self.get_encrypted_payload(
			method="bank_statement"
		)
		payload = {
			"accountStmtReq": encrypted_payload,
		}
		if checksum:
			payload["checksum"] = checksum

		response = requests.post(url, headers=headers, data=json.dumps(payload))

		log_id = create_api_log(
			response,
			action="Bank Statement",
			account_config=self.account_config,
			ref_doctype=self.doctype,
			ref_docname=self.name,
			unique_id=unique_id,
		)

		return self.get_decrypted_response(
			response, method="bank_statement", log_id=log_id
		)

	def update_account_config(self, method):
		method_map = {
			"make_payment": self.set_payment_data,
			"payment_status": self.set_payment_status_data,
			"bank_balance": self.set_balance_data,
			"bank_statement": self.set_statement_data,
		}

		if method in method_map:
			method_map[method]()  # update payload details

	def get_encrypted_payload(self, method):
		self.update_account_config(method)
		if not self.encrypted:
			return self.account_config, ""  # Payload is not encrypted
		plain_text = json.dumps(self.account_config)[1:-1]
		checksum = hashlib.sha256(plain_text.encode()).hexdigest()
		return self.aes_encrypt_data(plain_text, self.AES_KEY), checksum

	def get_decrypted_response(self, response, method, log_id=None):
		res_dict = frappe._dict({})
		if response.ok:
			if self.encrypted:
				decrypted_data = {}
				try:
					response_json = response.json()
					encrypted_response = response_json.get(self.status_key_map[method])
					if encrypted_response:
						aes_decrypted_data = self.aes_decrypt_data(
							encrypted_response, self.AES_KEY, json_loads=False
						)
						decrypted_data = {
							self.status_key_map[method]: json.loads(
								"{" + aes_decrypted_data + "}"
							)
						}
						self.set_decrypted_response(log_id, decrypted_data)
				except Exception:
					frappe.log_error(
						"Decryption Failed", frappe.get_traceback(with_context=1)
					)
				self.set_decrypted_response(log_id, decrypted_data)
			else:
				decrypted_data = response.json()
			self.get_formated_response(decrypted_data, res_dict, method)
		else:
			res_dict.status = "Request Failure"
			res_dict.message = response.text or response.status_code

		return res_dict

	def set_decrypted_response(self, log_id, response_data):
		if isinstance(response_data, str):
			response_data = json.loads(response_data)

		response_data = json.dumps(response_data, indent=4)
		super().set_decrypted_response(log_id=log_id, response_data=response_data)

	def get_mode_of_transfer(self, mode_of_transfer):
		if "A2A" in mode_of_transfer:
			mode_of_transfer = "IFT"

		return mode_of_transfer

	def set_payment_data(self):
		payment_details = self.payment_doc
		party = payment_details.party_name or payment_details.party
		remarks = (
			payment_details.remarks
			or f"Payment from {payment_details.parent} for {party}"
		)
		address_details = frappe._dict(payment_details.address_details or {})

		self.account_config.update(
			{
				"custTxnRef": payment_details.name,
				"beneAccNo": payment_details.bank_account_no,
				"beneID": "",
				"beneName": party,
				"beneAddr1": address_details.get("AddressLine", "")[
					:33
				],  # max length 35
				"beneAddr2": address_details.get("TownName", ""),
				"beneAddr3": address_details.get("Country", ""),
				"IFSC": payment_details.branch_code,
				"valueDate": getdate().strftime("%Y-%m-%d"),
				"txnDate": getdate().strftime("%Y-%m-%d"),
				"tranAmount": cstr(payment_details.amount),
				"remitInfo1": self.client_code,
				"paymentType": self.get_mode_of_transfer(
					payment_details.mode_of_transfer
				),
				"beneAccType": "CA",
				"remarks": remarks[:98],  # max length 100
				"beneMail": payment_details.email,
				"beneMobile": payment_details.mobile_no,
				"enrichment1": "",
				"enrichment2": "",
				"enrichment3": "",
				"enrichment4": "",
				"enrichment5": "",
				"reservedfield1": "",
				"reservedfield2": "",
				"reservedfield3": "",
				"reservedfield4": "",
				"reservedfield5": "",
				"debitAcNo": self.account_number,
				"isSubmbr": "N",
				"submbr_Rmtr_Name": "",
				"submbr_Rmtr_Acctype": "",
				"submbr_Rmtr_Purpcd": "",
				"submbr_Rmtr_Accno": "",
				"submbr_Rmtr_Addfld": "",
				"invDtlReq": "N",
			}
		)

	def set_payment_status_data(self):
		self.account_config.update(
			{
				"custRef": self.payment_doc.name,
				"bankRef": "",
				"cmsRef": "",
				"clientCode": self.client_code,
				"debitAcNo": self.account_number,
				"ddNo": "",
				"valueDate": "",
			}
		)

	def set_balance_data(self):
		self.account_config.update(
			{
				"accountNos": [
					{
						"accountNo": self.account_number,
					}
				]
			}
		)

	def set_statement_data(self):
		payload_details = self.doc
		from_date = getdate(payload_details.get("from_date", "")).strftime("%Y-%m-%d")
		to_date = getdate(payload_details.get("to_date", "")).strftime("%Y-%m-%d")

		self.account_config.update(
			{
				"accNo": self.account_number,
				"fromDate": from_date,
				"toDate": to_date,
				"paginationDetail": {
					"lastTxnDate": "",
					"lastTxnId": "",
					"lastTxnSrlNo": "",
					"lastTxnAmount": "",
					"lastPstdDate": "",
				},
			}
		)

	def get_formated_response(self, data, res_dict, method):
		if isinstance(data, str):
			data = json.loads(data)

		data = frappe._dict(data.get(self.status_key_map.get(method), {}))

		if method == "make_payment" and data:
			if data.status in ["S", "P", "F"]:
				res_dict.payment_status = "ACCEPTED"
				if data.errorCode in ["TXN000"]:
					res_dict.summary_details = {
						self.payment_doc.name: {"payment_status": "Accepted"}
					}
				elif data.errorCode in [
					"TXN001",
					"TXN002",
					"TXN003",
					"TXN007",
					"TXN998",
					"TXN999",
				]:
					res_dict.summary_details = {
						self.payment_doc.name: {
							"payment_status": "Request Failure",
							"message": data.errorDesc,
							"error_code": data.errorCode,
						}
					}
				elif data.errorCode:
					res_dict.summary_details = {
						self.payment_doc.name: {
							"payment_status": "Failed",
							"message": data.errorDesc,
							"error_code": data.errorCode,
						}
					}
				else:
					res_dict.summary_details = {
						self.payment_doc.name: {
							"payment_status": "Pending",
							"response": data,
						}
					}
			else:
				res_dict.status = "Failed"
				res_dict.message = data.get("errorDesc")

		elif method == "payment_status":
			if data.status in ["S", "F", "P"]:
				res_dict.payment_status = "PROCESSED"
				if data.errorCode == "ENQ000":
					res_dict.summary_details = {
						self.payment_doc.name: {
							"status": "Processed",
							"utr_number": data.bankRef,
							"processed_date": get_datetime(data.valDate).strftime(
								"%Y-%m-%d"
							),
							"message": data.statusDesc or "Payment Completed",
						}
					}
					if data.status == "P":
						res_dict.summary_details[self.payment_doc.name][
							"status"
						] = "Pending"
				elif data.errorCode in [
					"ENQ001",
					"ENQ002",
					"ENQ003",
					"ENQ007",
					"ENQ009",
					"ENQ998",
					"ENQ999",
				]:
					res_dict.summary_details = {
						self.payment_doc.name: {
							"status": "Pending",
							"response": data,
						}
					}
				elif data.errorCode in ["ENQ004", "ENQ005", "ENQ006"]:
					res_dict.summary_details = {
						self.payment_doc.name: {
							"payment_status": "Failed",
							"message": data.errorDesc,
							"error_code": data.errorCode,
						}
					}
			else:
				res_dict.status = "Failed"
				res_dict.message = data.get("errorCode", "") + data.get(
					"errorDesc", "Failed"
				)

		elif method == "bank_balance":
			if data and (balance_details_list := data.get("balanceDetails", [])):
				balance_details = balance_details_list[0]
				if balance_details and balance_details.get("respCode") == "000":
					res_dict.server_status = "Success"
					res_dict.balance = balance_details.get("availableBalance", 0)
					res_dict.date = getdate()
				else:
					res_dict.status = "Failed"
					res_dict.message = cstr(data.get("balanceDetails"))
			else:
				res_dict.status = "Failed"
				res_dict.message = data

		elif method == "bank_statement":
			if acc_statement := data.PaginatedAccountStatement:
				transactions = []
				transaction_details = acc_statement.get("transactionDetails", [])
				if transaction_details:
					for txn in transaction_details:
						amount = abs(flt(txn.get("txnAmt")))
						if txn.get("txnType").lower() == "d":
							amount = -1 * amount
						transaction = {
							"transaction_date": txn.get(
								"txnDate", txn.get("valueDate")
							),
							"transaction_amount": amount,
							"reference_number": txn.get("txnId"),
							"transaction_description": txn.get("txnDesc", ""),
						}
						transactions.append(transaction)
					res_dict.server_status = "Success"
					res_dict.bank_statements = transactions
				else:
					res_dict.status = "Failed"
					res_dict.message = acc_statement
			else:
				res_dict.status = "Failed"
				res_dict.message = data

	@frappe.whitelist()
	def get_api_endpoints(self):
		from india_banking_connector.default import BOB_ENCRYPTED_END_POINTS
		from india_banking_connector.install import decrypt

		decrypted = decrypt(BOB_ENCRYPTED_END_POINTS)
		stagin_or_prod = "testing" if self.testing else "production"
		endpoints = decrypted[self.bank][stagin_or_prod]["composite"]

		self.api_endpoints = []
		self.extend(
			"api_endpoints",
			[{"action": action, "url": url} for action, url in endpoints.items()],
		)
