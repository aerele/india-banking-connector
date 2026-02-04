import frappe
from frappe import bold
from frappe.model.document import Document

from india_banking_connector.utils import get_existing_doc, get_id


class BaseHost(Document):
	def is_h2h_enabled(self):
		if not self.active:
			frappe.throw(
				f"{bold(self.name)} is not active. Please enable the host to initiate payment."
			)

	def get_response(self, method):
		self.is_h2h_enabled()
		if method and hasattr(self, method):
			return getattr(self, method)()
		else:
			frappe.throw(f"Unknown method {method} in host {self.name}")

	def get_payment_status(self):
		payment_details = frappe._dict(self.doc)
		unique_id = get_id(payment_details.name)

		existing_payment = get_existing_doc("Payment Log", unique_id)

		if existing_payment:
			return existing_payment.get_summary_details(action="get_payment_status")

		return {"message": "Payment not found"}
