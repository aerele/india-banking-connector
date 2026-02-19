# Copyright (c) 2026, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

import hashlib
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
			"x-fapi-epoch-millis": get_current_time_in_milliseconds(),
			"x-fapi-channel-id": self.channel_id,
			"x-fapi-uuid": get_id(15),
			"x-fapi-serviceId": "OpenApi",
			"x-fapi-serviceVersion": "1.0",
			"X-IBM-Client-Id": self.client_id,
			"X-IBM-Client-Secret": self.get_password("client_secret"),
			"content-type": "text/plain",
		}

	def initiate_payment(self):
		payment_details = self.doc if self.bulk_transaction else self.payment_doc
		unique_id = "".join(re.findall(r"[0-9a-zA-Z]", payment_details.name))

		if existing_payment_response := self.validate_duplicate_payments(
			unique_id=unique_id,
		):
			return existing_payment_response

		url = self.urls.make_payment
		headers = self.headers
		payload = self.get_encrypted_payload(method="make_payment")

		response = requests.post(url, headers=headers, data=payload)

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
			return [summary.name for summary in payment_doc.summary]

		return [
			{
				"txnPaymode": self.get_payment_mode(summary.mode_of_transfer),
				"custUniqRef": summary.name,
				"corpAccNum": self.account_number,
				"valueDate": getdate().strftime("%y-%m-%d"),
				"txnAmount": flt(summary.amount, 2),
				"beneLEI": "",
				"beneName": summary.party_name or summary.party,
				"beneCode": summary.party,
				"beneAccNum": summary.bank_account_no,
				"beneAcType": "",
				"beneAddr1": "",
				"beneAddr2": "",
				"beneAddr3": "",
				"beneCity": "",
				"beneState": "",
				"benePincode": "",
				"beneIfscCode": summary.branch_code,
				"beneBankName": summary.bank,
				"baseCode": "",
				"chequeNumber": "",
				"chequeDate": "",
				"payableLocation": "",
				"printLocation": "",
				"beneEmailAddr1": summary.email,
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

	def get_decrypted_response(self, method, response, log_id=None):
		res_dict = frappe._dict({})
		if response.ok:
			jws_verified = self.jws_verify(
				response.text, self.get_file_content(self.public_key)
			)

			jwe_decrypted = self.jwe_decrypt(
				jws_verified, self.get_file_content(self.private_key)
			)

			self.set_decrypted_response(log_id, jwe_decrypted)
			self.get_formated_response(jwe_decrypted, res_dict, method)
		else:
			res_dict.status = "Request Failure"
			res_dict.error = response.text

		return res_dict

	def format_payment_response(self, decrypted_data, res_dict):
		pass

	def format_payment_status_response(self, decrypted_data, res_dict):
		pass

	def get_formated_response(self, decrypted_data, res_dict, method):
		method_map = {
			"make_payment": self.format_payment_response,
			"payment_status": self.format_payment_status_response,
		}

		if method in method_map:
			method_map[method](decrypted_data, res_dict)

	def get_payment_status(self):
		pass

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
		print(decrypted)
		self.extend(
			"api_endpoints",
			[{"action": action, "url": url} for action, url in decrypted.items()],
		)
