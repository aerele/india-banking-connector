# Copyright (c) 2026, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

import frappe

from india_banking_connector.connectors.bank_connector import BankConnector


class AxisBankConnector(BankConnector):
	def __init__(self, *args, **kwargs):
		self.bank = "Axis Bank"
		super().__init__(*args, **kwargs)

		self.bulk_transaction = kwargs.get("bulk_transaction")
		self.doc = frappe._dict(kwargs.get("doc", {}))
		self.payment_doc = frappe._dict(kwargs.get("payment_doc", {}))

		self.account_config = {}

	def initiate_payment(self):
		pass

	def get_payment_status(self):
		pass

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
