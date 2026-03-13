# Copyright (c) 2026, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

import json
import re
from base64 import b64encode

import frappe
import requests
from frappe.utils import cstr, get_datetime, getdate
from jose.constants import ALGORITHMS

from india_banking_connector.connectors.bank_connector import BankConnector
from india_banking_connector.india_banking_connector.doctype.bank_request_log.bank_request_log import (
	create_api_log,
)


class CanaraBankConnector(BankConnector):
	bank = "Canara Bank"

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		self.bulk_transaction = kwargs.get("bulk_transaction")
		self.doc = frappe._dict(kwargs.get("doc", {}))
		self.payment_doc = frappe._dict(kwargs.get("payment_doc", {}))

		self.account_config = {}

		self.AES_KEY = bytes.fromhex(self.get_password("aes_key"))

	@property
	def urls(self):
		return super().urls

	@property
	def headers(self):
		cert = self.get_file_content(self.cert)
		cert_key = (
			cert.lstrip("-----BEGIN CERTIFICATE-----")
			.rstrip("-----END CERTIFICATE-----")
			.strip()
		)  # normalise

		return {
			"x-client-id": self.get_password("client_id"),
			"x-client-secret": self.get_password("client_secret"),
			"x-client-certificate": cert_key,
			"x-api-interaction-id": "1",
			"x-timestamp": cstr(int(get_datetime().timestamp() * 1000)),
			"x-signature": "",
			"Content-Type": "application/json",
		}

	def get_auth(self):
		auth_string = (
			self.get_password("client_id") + ":" + self.get_password("client_secret")
		)
		return b64encode(auth_string.encode()).decode()

	def initiate_payment(self):
		payment_details = self.doc
		unique_id = "".join(re.findall(r"[0-9a-zA-Z]", payment_details.name))

		if existing_payment_response := self.validate_duplicate_payments(
			unique_id=unique_id,
		):
			return existing_payment_response

		url = self.urls.make_payment
		headers = self.headers

		signature, payload = self.get_encrypted_payload(method="make_payment")
		headers["x-signature"] = signature

		response = requests.post(
			url, headers=headers, json=payload, cert=self.get_cert()
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
		encrypted = self.jwe_encrypt(
			self.account_config["Request"]["body"]["encryptData"],
			self.get_file_content(self.AES_KEY),
			encryption=ALGORITHMS.A128CBC_HS256,
			algorithm=ALGORITHMS.A256KW,
		)

		payload = {
			"Request": {
				"body": {
					"branchCode": self.branch_code,
					"encryptData": encrypted.decode("utf-8"),
				}
			}
		}

		return (
			self.generate_signature(
				self.account_config, self.get_file_content(self.private_key)
			),
			payload,
		)

	def get_decrypted_response(self, response, method: str, log_id: str):
		res_dict = frappe._dict({})
		if response.ok:
			decrypted_data = frappe._dict({})
			try:
				response = json.loads(response.text)
				encrypted_data = (
					response.get("Response", {}).get("body", {}).get("encryptData", "")
				)
				if not encrypted_data:
					res_dict.status = "FAILED"
					res_dict.message = "Data Not Found!"

				decrypted_data = self.jwe_decrypt(
					encrypted_data,
					self.AES_KEY,
				)
				self.set_decrypted_response(log_id, decrypted_data)
			except Exception:
				frappe.log_error(
					"Decryption Failed", frappe.get_traceback(with_context=1)
				)
				res_dict.status = "FAILED"
				res_dict.message = "Response Decryption Failed!"
				return res_dict

			self.get_formated_response(decrypted_data, res_dict, method)
		else:
			res_dict.status = "Request Failure"
			res_dict.message = response.text or response.status_code

		return res_dict

	def update_account_config(self, method):
		method_map = {
			"make_payment": self.set_payment_data,
			"payment_status": self.set_payment_status_data,
			"bank_balance": self.set_balance_data,
			"bank_statement": self.set_statement_data,
		}

		if method in method_map:
			method_map[method]()

	def set_payment_data(self):
		self.account_config.update({})

	def set_payment_status_data(self):
		self.account_config.update({})

	def set_balance_data(self):
		self.account_config.update(
			{
				"Request": {
					"body": {
						"branchCode": self.branch_code,
						"encryptData": {
							"Authorization": "Basic " + self.get_auth(),
							"acctNumber": self.account_number,
							"customerID": self.customer_id,
							"key": self.customer_key,
						},
					}
				}
			}
		)

	def set_statement_data(self):
		payload_details = self.doc

		from_date = getdate(payload_details.get("from_date", "")).strftime("%d-%m-%Y")
		to_date = getdate(payload_details.get("to_date", "")).strftime("%d-%m-%Y")
		self.account_config.update(
			{
				"Request": {
					"body": {
						"encryptData": {
							"Authorization": "Basic " + self.get_auth(),
							"acctNumber": self.account_number,
							"customerID": self.customer_id,
							"NUMBEROFTXN": "n",
							"FROMDATE": from_date,
							"TODATE": to_date,
							"searchBy": "",
							"branchCode": self.branch_code,
							"key": self.customer_key,
						}
					}
				}
			}
		)

	def get_formated_response(self, decrypted_data, res_dict, method):
		method_map = {
			"make_payment": self.format_payment_response,
			"payment_status": self.format_payment_status_response,
			"bank_balance": self.format_bank_balance_response,
			"bank_statement": self.format_statement_response,
		}

		if method in method_map:
			method_map[method](decrypted_data, res_dict)

	def format_payment_response(self, decrypted_data, res_dict):
		pass

	def format_payment_status_response(self, decrypted_data, res_dict):
		pass

	def format_bank_balance_response(self, decrypted_data, res_dict):
		pass

	def format_statement_response(self, decrypted_data, res_dict):
		pass
