# Copyright (c) 2024, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

# import frappe
from frappe.model.document import Document


class ICICIConnector(Document):
	def intiate_payment(self):
		return "Payment Intiate Not Implemented"

	def get_payment_status(self):
		return "Payment Status Not Implemented"

	def get_transaction_history(self):
		return "Transaction History Not Implemented"

	def get_balance(self):
		return "Balance Not Implemented"

	def get_oauth_token(self):
		return "OAuth Token Not Implemented"
