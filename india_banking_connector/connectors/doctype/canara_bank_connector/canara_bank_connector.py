# Copyright (c) 2026, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

import frappe
from frappe.utils import cstr, get_datetime

from india_banking_connector.connectors.bank_connector import BankConnector


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
