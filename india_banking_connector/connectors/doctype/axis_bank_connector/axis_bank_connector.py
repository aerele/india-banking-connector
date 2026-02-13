# Copyright (c) 2026, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

import frappe
from frappe.model.document import Document


class AxisBankConnector(Document):
	def __init__(self, *args, **kwargs):
		self.bank = "Axis Bank"
		super().__init__(*args, **kwargs)

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
