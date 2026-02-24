# Copyright (c) 2026, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

import hashlib
import json
import re

import frappe
import requests
from frappe.query_builder import DocType
from frappe.utils import cstr, flt, getdate

from india_banking_connector.connectors.bank_connector import BankConnector
from india_banking_connector.india_banking_connector.doctype.bank_request_log.bank_request_log import (
	create_api_log,
)
from india_banking_connector.utils import get_current_time_in_milliseconds, get_id


class AxisBankConnector(BankConnector):
	def __init__(self, *args, **kwargs):
		self.bank = "Axis Bank"
		super().__init__(*args, **kwargs)

		self.bulk_transaction = kwargs.get("bulk_transaction")
		self.doc = frappe._dict(kwargs.get("doc", {}))
		self.payment_doc = frappe._dict(kwargs.get("payment_doc", {}))

		self.account_config = {}

	@property
	def urls(self):
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

	@property
	def headers(self):
		return {
			"x-fapi-epoch-millis": cstr(get_current_time_in_milliseconds()),
			"x-fapi-channel-id": self.channel_id,
			"x-fapi-uuid": get_id(15),
			"x-fapi-serviceId": "OpenApi",
			"x-fapi-serviceVersion": "1.0",
			"X-IBM-Client-Id": self.client_id,
			"X-IBM-Client-Secret": self.get_password("client_secret"),
			"content-type": "text/plain",
		}

	def initiate_payment(self):
		payment_details = self.doc
		unique_id = "".join(re.findall(r"[0-9a-zA-Z]", payment_details.name))

		if existing_payment_response := self.validate_duplicate_payments(
			unique_id=unique_id,
		):
			return existing_payment_response

		url = self.urls.make_payment
		headers = self.headers
		payload = self.get_encrypted_payload(method="make_payment")

		response = requests.post(
			url, headers=headers, data=payload, cert=self.get_cert()
		)

		log_id = create_api_log(
			response,
			action="Initiate Payment",
			account_config=self.account_config,
			ref_doctype=payment_details.doctype,
			ref_docname=payment_details.name,
			unique_id=unique_id,
			connector=self,
		)

		return self.get_decrypted_response(
			response, method="make_payment", log_id=log_id
		)

	def get_encrypted_payload(self, method):
		self.update_account_config(method)
		# Encrypt Payload
		encrypted = self.jwe_encrypt(
			self.account_config,
			self.get_file_content(self.public_key),
		)
		# Sign the Encypted Payload
		return self.sign_jws(
			encrypted,
			self.get_file_content(self.private_key),
		)

	def update_account_config(self, method):
		method_map = {
			"make_payment": self.set_payment_data,
			"payment_status": self.set_payment_status_data,
		}

		if method in method_map:
			method_map[method]()

	def build_checksum_string(self, data: dict | list | str) -> str:
		"""build checksum string."""
		result = []

		if isinstance(data, dict):
			for key, value in data.items():
				if key == "checksum":
					continue  # skip checksum field
				result.append(self.build_checksum_string(value))
		elif isinstance(data, list):
			for item in data:
				result.append(self.build_checksum_string(item))
		else:
			# primitive value
			result.append(cstr(data))

		return "".join(result)

	def hash_data(self, text: bytes | str, mode="md5") -> str:
		if isinstance(text, str):
			text = text.encode()

		return hashlib.md5(text).hexdigest()

	def generate_checksum(self, data: dict) -> str:
		checksum_string = self.build_checksum_string(data)
		return self.hash_data(checksum_string)

	def set_payment_data(self):
		self.account_config.update(
			{
				"Data": {
					"channelId": self.channel_id,
					"corpCode": self.corp_id,
					"paymentDetails": self.get_transactions(),
				},
				"Risk": {},
			}
		)
		# Update checksum
		self.account_config["Data"]["checksum"] = self.generate_checksum(
			self.account_config["Data"]
		)

	def get_payment_mode(self, mode_of_transfer: str) -> str:
		mode_of_transfer = mode_of_transfer.lower()
		payment_mode = None
		if "a2a" in mode_of_transfer:
			payment_mode = "FT"
		elif "imps" in mode_of_transfer:
			payment_mode = "PA"
		elif "neft" in mode_of_transfer:
			payment_mode = "NE"
		elif "rtgs" in mode_of_transfer:
			payment_mode = "RT"

		return payment_mode

	def get_transactions(self, id_only=False) -> list:
		payment_doc = self.doc

		if id_only:
			return [summary.get("name") for summary in payment_doc.summary]

		return [
			{
				"txnPaymode": self.get_payment_mode(summary.get("mode_of_transfer")),
				"custUniqRef": summary.get("name"),
				"corpAccNum": self.account_number,
				"valueDate": getdate().strftime("%Y-%m-%d"),
				"txnAmount": cstr(flt(summary.get("amount"), 2)),
				"beneLEI": "",
				"beneName": summary.get("party_name") or summary.get("party"),
				"beneCode": get_id(summary.get("party")).upper(),
				"beneAccNum": summary.get("bank_account_no"),
				"beneAcType": "",
				"beneAddr1": "",
				"beneAddr2": "",
				"beneAddr3": "",
				"beneCity": "",
				"beneState": "",
				"benePincode": "",
				"beneIfscCode": summary.get("branch_code"),
				"beneBankName": summary.get("bank"),
				"baseCode": "",
				"chequeNumber": "",
				"chequeDate": "",
				"payableLocation": "",
				"printLocation": "",
				"beneEmailAddr1": summary.get("email"),
				"beneMobileNo": summary.get("mobile", ""),
				"productCode": "",
				"txnType": "",
				"invoiceDetails": [
					{
						"invoiceAmount": "",
						"invoiceNumber": "",
						"invoiceDate": "",
						"cashDiscount": "",
						"tax": "",
						"netAmount": "",
						"invoiceInfo1": "",
						"invoiceInfo2": "",
						"invoiceInfo3": "",
						"invoiceInfo4": "",
						"invoiceInfo5": "",
					}
				],
				"enrichment1": "",
				"enrichment2": "",
				"enrichment3": "",
				"enrichment4": "",
				"enrichment5": "",
				"senderToReceiverInfo": "",
			}
			for summary in payment_doc.summary
		]

	def get_decrypted_response(self, response, method, log_id=None):
		res_dict = frappe._dict({})
		try:
			jws_verified = self.jws_verify(
				response.text, self.get_file_content(self.public_key)
			)
			jwe_decrypted = self.jwe_decrypt(
				jws_verified, self.get_file_content(self.private_key)
			).decode()
			self.set_decrypted_response(log_id, jwe_decrypted)
			self.get_formated_response(jwe_decrypted, res_dict, method)
		except Exception:
			frappe.log_error(
				"Axis Bank response decryption/verification failed",
				frappe.get_traceback(with_context=True),
			)
			res_dict.status = "Decryption Failure"
			res_dict.error = "Failed to verify or decrypt bank response."
		
		return res_dict

	def format_payment_response(self, decrypted_data, res_dict):
		if isinstance(decrypted_data, str):
			try:
				decrypted_data = json.loads(decrypted_data)
			except json.JSONDecodeError:
				try:
					decrypted_data = decrypted_data.replace("'", '"')
					decrypted_data = json.loads(decrypted_data)
				except json.JSONDecodeError:
					res_dict.status = "Failure"
					res_dict.message = "Failed to parse payment response."
					return

		decrypted_data = frappe._dict(decrypted_data)

		status = decrypted_data.get("Data", {}).get("status", "")
		message = decrypted_data.get("Data", {}).get("message", "")

		if status == "S":
			res_dict.payment_status = "ACCEPTED"
			res_dict.message = "Payment initiated successfully."
			res_dict.summary_details = self.get_summary_details("Accepted")
		elif status == "F":
			res_dict.payment_status = "FAILED"
			res_dict.message = message
			res_dict.summary_details = self.get_summary_details("Failed")
		else:
			res_dict.status = "Request Failure"
			res_dict.message = "Unexpected response format."

	def get_status(self, status_code):
		status = "Pending"
		if status_code == "PROCESSED":
			status = "Processed"
		elif status_code in ["REJECTED", "RETURN"]:
			status = "Failed"

		return status

	def format_payment_status_response(self, decrypted_data, res_dict):
		if isinstance(decrypted_data, str):
			try:
				decrypted_data = json.loads(decrypted_data)
			except json.JSONDecodeError:
				try:
					decrypted_data = decrypted_data.replace("'", '"')
					decrypted_data = json.loads(decrypted_data)
				except json.JSONDecodeError:
					res_dict.status = "Failure"
					res_dict.message = "Failed to parse payment response."
					return

		data = decrypted_data.get("Data", {})

		if data and data.get("status") == "S":
			res_dict.payment_status = "PROCESSED"
			res_dict.message = "Payment status fetched successfully."
		else:
			res_dict.payment_status = "Request Failure"
			res_dict.message = "Invalid response format."

		summary_details = {}
		transactions = data.get("data", {}).get("CUR_TXN_ENQ") or []
		for transaction in transactions:
			transaction = frappe._dict(transaction)
			summary_details[transaction.crn] = {
				"unique_id": transaction.crn,
				"status_code": transaction.responseCode,
				"status": self.get_status(transaction.transactionStatus),
				"utr_number": transaction.utrNo,
				"message": transaction.statusDescription,
			}

		res_dict.summary_details = summary_details

		return res_dict

	def get_formated_response(self, decrypted_data, res_dict, method):
		method_map = {
			"make_payment": self.format_payment_response,
			"payment_status": self.format_payment_status_response,
		}

		if method in method_map:
			method_map[method](decrypted_data, res_dict)

	def get_payment_status(self):
		payment_details = self.doc
		unique_id = "".join(re.findall(r"[0-9a-zA-Z]", payment_details.name))

		url = self.urls.payment_status
		headers = self.headers
		payload = self.get_encrypted_payload(method="payment_status")

		response = requests.post(
			url, headers=headers, data=payload, cert=self.get_cert()
		)

		log_id = create_api_log(
			response,
			action="Get Payment Status",
			account_config=self.account_config,
			ref_doctype=payment_details.doctype,
			ref_docname=payment_details.name,
			unique_id=unique_id,
			connector=self,
		)

		return self.get_decrypted_response(
			response, method="payment_status", log_id=log_id
		)

	def set_payment_status_data(self):
		self.account_config.update(
			{
				"Data": {
					"channelId": self.channel_id,
					"corpCode": self.corp_id,
					"crn": self.get_transactions(id_only=True),
				}
			}
		)

		# Update checksum
		self.account_config["Data"]["checksum"] = self.generate_checksum(
			self.account_config["Data"]
		)

	def get_bank_balance(self):
		frappe.throw(
			"Bank Balance API is not currently supported by the Axis Bank Connector."
		)

	def get_bank_statement(self):
		frappe.throw(
			"Bank statement API is not currently supported by the Axis Bank Connector."
		)

	@frappe.whitelist()
	def get_api_endpoints(self):
		from india_banking_connector.default import AXIS_ENCRYPTED_END_POINTS
		from india_banking_connector.install import decrypt

		decrypted = decrypt(AXIS_ENCRYPTED_END_POINTS)
		self.extend(
			"api_endpoints",
			[{"action": action, "url": url} for action, url in decrypted.items()],
		)
