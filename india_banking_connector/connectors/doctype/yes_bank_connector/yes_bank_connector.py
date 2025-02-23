# Copyright (c) 2024, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

import json
from base64 import b64encode

import frappe
import requests

from india_banking_connector.connectors.bank_connector import BankConnector
from india_banking_connector.india_banking_connector.doctype.bank_request_log.bank_request_log import (
	create_api_log,
)


class YESBANKConnector(BankConnector):
	bank = "YES Bank"

	__all__ = ["initiate_payment", "get_payment_status"]

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		self.bulk_transaction = kwargs.get("bulk_transaction")
		self.doc = frappe._dict(kwargs.get("doc", {}))
		self.payment_doc = frappe._dict(kwargs.get("payment_doc", {}))

	@property
	def urls(self):
		if self.bulk_transaction:
			frappe.throw("Bulk transactions are not Tested")

		return super().urls

	@property
	def headers(self):
		bareer_token = b64encode(f"{self.get_password('user_name')}:{self.get_password('password')}".encode())
		return {
			"X-IBM-Client-Id": self.get_password("client_key"),
			"X-IBM-Client-Secret": self.get_password("client_secret"),
			"Authorization": f"Basic {bareer_token.decode()}",
			"Content-Type": "application/json",
		}

	def initiate_payment(self):
		payment_details = self.payment_doc if not self.bulk_transaction else self.doc

		url = self.urls.make_payment
		headers = self.headers
		payload = self.get_payload(method="make_payment")

		response = requests.post(
			url, headers=headers, data=payload, cert=self.get_cert()
		)

		create_api_log(
			response,
			action="Initiate Payment",
			account_config=self.get_payload(method="make_payment"),
			ref_doctype=payment_details.parenttype or payment_details.doctype,
			ref_docname=payment_details.parent or payment_details.name,
		)

		return self.get_verified_response(response, method="make_payment")

	def get_payment_status(self):
		payment_details = self.payment_doc if not self.bulk_transaction else self.doc

		url = self.urls.payment_status
		headers = self.headers
		payload = self.get_payload(method="payment_status")

		response = requests.post(url, headers=headers, data=payload)

		create_api_log(
			response,
			action="Payment Status",
			account_config=self.get_payload("payment_status"),
			ref_doctype=payment_details.parenttype or payment_details.doctype,
			ref_docname=payment_details.parent or payment_details.name,
		)

		return self.get_verified_response(response, method="payment_status")

	def get_bank_balance(self):
		payment_details = self.payment_doc if not self.bulk_transaction else self.doc

		url = self.urls.bank_balance
		headers = self.headers
		payload = self.get_payload(method="bank_balance")

		response = requests.post(url, headers=headers, data=payload)

		create_api_log(
			response,
			action="Bank Balance",
			account_config=self.get_payload("bank_balance"),
			ref_doctype=payment_details.parenttype or payment_details.doctype,
			ref_docname=payment_details.parent or payment_details.name,
		)

		return self.get_verified_response(response, method="bank_balance")

	def get_payload(self, method):
		if method == "make_payment":
			return self.get_payment_payload()
		elif method == "payment_status":
			return self.get_status_payload()
		elif method == "bank_balance":
			return self.get_bank_balance_payload()

	def get_bank_balance_payload(self):
		conector_doc = self

		return json.dumps(
			{
				"Data": {
					"DebtorAccount": {
						"ConsentId": conector_doc.user_id,
						"Identification": conector_doc.account_number,
						"SecondaryIdentification": conector_doc.user_id,
					}
				}
			}
		)

	def get_payment_payload(self):
		conector_doc = self
		payment_details = self.payment_doc if not self.bulk_transaction else self.doc

		if "A2A" in payment_details.mode_of_transfer:
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
							"Currency": "INR",
						},
						"DebtorAccount": {
							"Identification": conector_doc.account_number,
							"SecondaryIdentification": conector_doc.user_id,
						},
						"CreditorAccount": {
							"SchemeName": payment_details.branch_code,
							"Identification": payment_details.bank_account_no,
							"Name": payment_details.party,
							"Unstructured": {
								"ContactInformation": {
									"EmailAddress": payment_details.email,
									"MobileNumber": payment_details.get(
										"mobile_no", ""
									),
								}
							},
						},
						"RemittanceInformation": {
							"Reference": payment_details.name,
							"Unstructured": {
								"CreditorReferenceInformation": "RemeToBeneInfo"
							},
						},
						"ClearingSystemIdentification": mode_of_transfer,
					},
				},
				"Risk": {
					"DeliveryAddress": json.loads(payment_details.get("address", "{}")),
				},
			}
		)

	def get_status_payload(self):
		conector_doc = self
		payment_details = self.payment_doc if not self.bulk_transaction else self.doc

		return json.dumps(
			{
				"Data": {
					"InstrId": payment_details.name,
					"ConsentId": conector_doc.user_id,
					"SecondaryIdentification": conector_doc.user_id,
				}
			}
		)

	def get_verified_response(self, response, method):
		res_dict = frappe._dict({})
		if response.ok:
			response_data = response.json()
			if method == "make_payment":
				status = response_data.get("Data", {}).get("Status")
				if status == "Received":
					res_dict.payment_status = "ACCEPTED"
					res_dict.message = "Payment Accepted"
					res_dict.summary_details = {
						self.payment_doc.name: {
							"payment_status": "Accepted",
							"message": "Payment Rejected due to Dublicate ID",
						}
					}
				elif status == "Duplicate":
					res_dict.payment_status = "ACCEPTED"
					res_dict.summary_details = {
						self.payment_doc.name: {
							"payment_status": "Failed",
							"message": "Payment Rejected due to Dublicate ID",
						}
					}

			elif method == "payment_status":
				res_dict.payment_status = "PROCESSED"
				msg, utr, sts = self.get_msg_utr_number(response_data)
				res_dict.summary_details = {
					self.payment_doc.name: {
						"status": sts,
						"message": msg,
						"utr_number": utr,
					}
				}

			elif method == "bank_balance":
				balance = (
					response_data.get("Data", {})
					.get("FundsAvailableResult", {})
					.get("BalanceAmount", "")
				)
				res_dict.update({"balance": balance})
		else:
			res_dict.update({"status": "Request Failure", "error": response.text})

		return res_dict

	def get_msg_utr_number(self, data):
		msg, utr, sts = "Payment Status Not Available", None, "Request Failure"

		data_initiation = data.get("Data", {}).get("Initiation", {})
		data_status = data.get("Data", {}).get("Status", "")

		utr = data_initiation.get("EndToEndIdentification", None)
		msg = data_status if data_status else msg

		if data_status in ["SettlementInProcess", "Pending", "Pending Auth"]:
			sts = "Pending"
		elif data_status == "SettlementCompleted":
			sts = "Processed"
		elif data_status in ["SettlementReversed", "FAILED"]:
			sts = "Failed"

		return msg, utr, sts

	def get_cert(self):
		return (
			self.get_file_relative_path(self.cert_file),
			self.get_file_relative_path(self.private_key),
		)

	def get_transaction_history(self):
		return "Transaction History Not Implemented"
