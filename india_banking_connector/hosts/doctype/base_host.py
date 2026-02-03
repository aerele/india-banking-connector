import frappe
from frappe import bold
from frappe.model.document import Document


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
