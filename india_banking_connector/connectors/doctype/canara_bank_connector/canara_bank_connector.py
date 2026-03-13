# Copyright (c) 2026, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

import re

import frappe
import requests
from frappe.utils import cstr, get_datetime

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
			"x-client-id": self.client_id,
			"x-client-secret": self.get_password("client_secret"),
			"x-client-certificate": cert_key,
			"x-api-interaction-id": "1",
			"x-timestamp": cstr(int(get_datetime().timestamp() * 1000)),
			"x-signature": "",
			"Content-Type": "application/json",
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
		pass

	def get_decrypted_response(self, response, method, log_id=None):
		pass
