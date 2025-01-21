# Copyright (c) 2025, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

# import frappe
from frappe.model.document import Document


class BankAPIEndpoint(Document):
	def autoname(self):
		self.name = f"{self.bank}-{self.environment}-{"Bulk" if self.bulk_transaction else 'Composite'}"
