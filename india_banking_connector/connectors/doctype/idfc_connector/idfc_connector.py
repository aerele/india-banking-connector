# Copyright (c) 2025, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

import re

import frappe
import jwt
import requests
from frappe import _
from frappe.query_builder import DocType
from frappe.utils import add_to_date, get_datetime

from india_banking_connector.connectors.bank_connector import BankConnector
from india_banking_connector.india_banking_connector.doctype.bank_request_log.bank_request_log import (
	create_api_log,
)


class IDFCConnector(BankConnector):
	__all__ = [
		"initiate_payment",
		"get_payment_status",
	]

	def __init__(self, *args, **kwargs):
		self.bank = "IDFC"
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
			"source": self.corp_id,
			"correlationId": frappe.generate_hash(length=20),
			"Content-Type": "application/octet-stream",
			"Timestamp": int(get_datetime().timestamp()),
			"tran_id": self.transaction_id,
			"corp_id": self.corp_id,
			"Authorization": "Bearer " + self.get_oauth_token(),
		}

	@frappe.whitelist()
	def get_oauth_token(self):
		headers = {
			"Accept": "application/json",
			"Content-Type": "application/x-www-form-urlencoded",
		}

		data = {
			"grant_type": "client_credentials",
			"scope": self.scope,
			"client_id": self.get_password("client_id"),
			"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			"client_assertion": self.get_client_assertion(),
		}

		try:
			response = requests.post(
				self.urls.oauth_token,
				headers=headers,
				data=data,
			)

			create_api_log(response, action="Get OAuth Token", account_config=data)

			if response.ok:
				return response.json().get("access_token")
		except Exception:
			frappe.log_error("Oauth Failed", frappe.get_traceback(with_context=True))
			frappe.throw(
				_(
					"Connection failed. Unable to authenticate with the connector. Please verify your credentials"
				)
			)

	def get_client_assertion(self):
		headers = {
			"alg": "RS256",
			"typ": "JWT",
			"kid": self.get_password("signing_key"),
		}
		payload = {
			"jti": frappe.generate_hash(length=30),
			"sub": self.get_password("client_id"),
			"iss": self.get_password("client_id"),
			"aud": self.urls.get("oauth_token"),
			"exp": int(add_to_date().timestamp()) + 60,  # 60 seconds from current time
		}

		return jwt.encode(
			payload,
			self.get_file_content(self.private_key),
			algorithm="RS256",
			headers=headers,
		)

	def initiate_payment(self):
		payment_details = self.doc if self.bulk_transaction else self.payment_doc
		unique_id = "".join(re.findall(r"[0-9a-zA-Z]", payment_details.name))
		self.transaction_id = "NEFT" + unique_id

		if existing_payment_response := self.validate_duplicate_payments(
			unique_id=self.transaction_id,
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
		)

		return self.get_decrypted_response(
			response, method="make_payment", log_id=log_id
		)

	def get_encrypted_payload(self, method: str):
		self.__aes_key = bytes.fromhex(self.get_password("aes_key"))
		self.update_account_config(method)
		return self.aes_encrypt_data(self.account_config, self.__aes_key)

	def get_decrypted_response(self, response, method: str, log_id: str):
		res_dict = frappe._dict({})
		if response.ok:
			decrypted_data = frappe._dict({})
			try:
				decrypted_data = self.aes_decrypt_data(
					response.text, self.get_password("aes_key"), json_loads=True
				)
				self.set_decrypted_response(log_id, decrypted_data)
			except Exception:
				frappe.log_error(
					"Decryption Failed", frappe.get_traceback(with_context=1)
				)
				res_dict.status = "failed"
				res_dict.message = "Response Decryption Failed!"
				return res_dict

			self.get_formated_response(decrypted_data, res_dict, method)
		else:
			res_dict.status = "Request Failure"
			res_dict.message = response.text or response.status_code

		return res_dict

	def get_formated_response(self, decrypted_data, res_dict, method):
		method_map = {
			"make_payment": self.format_payment_response,
			"payment_status": self.format_payment_status_response,
		}

		if method in method_map:
			method_map[method](decrypted_data, res_dict)

	def format_payment_response(self, decrypted_data, res_dict):
		pass

	def format_payment_status_response(self, decrypted_data, res_dict):
		pass

	def update_account_config(self, method):
		method_map = {
			"make_payment": self.set_payment_data,
			"payment_status": self.set_payment_status_data,
		}

		if method in method_map:
			method_map[method]()

	def set_payment_data(self):
		self.account_config.update(
			{
				"doMultiPaymentCorpReq": {
					"Header": {
						"Maker_ID": self.maker_id,
						"Checker_ID": self.checker_id,
						"Approver_ID": self.approver_id,
					},
					"Body": {
						"Payment": [
							{
								"RefNo": payment.name,
								"Amount": payment.amount,
								"Debit_Acct_No": self.account_number,
								"Debit_Acct_Name": self.account_holder_name,
								"Debit_Mobile": self.mobile_number or "",
								"Ben_IFSC": payment.branch_code,
								"Ben_Acct_No": payment.bank_account_no,
								"Ben_Name": payment.party_name or payment.party,
								"Ben_BankName": payment.party_name or payment.party,
								"Ben_Email": payment.email or "",
								"Ben_Mobile": payment.mobile_no or "",
								"Mode_of_Pay": "NEFT",
								"Nature_of_Pay": "MPYMT",
								"Remarks": f"Payment from {payment.parent} for {payment.party_name or payment.party}",
							}
							for payment in self.doc.get("summary", [])
						]
					},
				}
			}
		)

	def set_payment_status_data(self):
		unique_id = "".join(re.findall(r"[0-9a-zA-Z]", self.doc.name))
		transaction_id = "NEFT" + unique_id
		self.account_config.update(
			{
				"doMultiPaymentCorpReq": {
					"Header": {
						"Maker_ID": self.maker_id,
						"Checker_ID": self.checker_id,
						"Approver_ID": self.approver_id,
					},
					"Body": {
						"Tran_ID": transaction_id,
					},
				}
			}
		)

	@frappe.whitelist()
	def get_api_endpoints(self):
		from india_banking_connector.default import IDFC_ENCRYPTED_END_POINTS
		from india_banking_connector.install import decrypt

		decrypted = decrypt(IDFC_ENCRYPTED_END_POINTS)
		print(decrypted)
		stagin_or_prod = "testing" if self.testing else "production"
		endpoints = decrypted[self.bank][stagin_or_prod]["composite"]

		self.api_endpoints = []
		self.extend(
			"api_endpoints",
			[{"action": action, "url": url} for action, url in endpoints.items()],
		)
