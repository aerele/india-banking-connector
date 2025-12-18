# Copyright (c) 2025, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

import frappe
from frappe.model.document import Document


class IDFCConnector(Document):
	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.bank = "IDFC"

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
