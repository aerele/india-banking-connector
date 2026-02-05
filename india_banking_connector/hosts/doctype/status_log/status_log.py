# Copyright (c) 2026, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

import json

import frappe
from frappe.model.document import Document


class StatusLog(Document):
	def update_payment_status(self):
		if self.formatted_data:
			for unique_id, data in json.loads(self.formatted_data).items():
				if log_summary := frappe.db.exists(
					"Payment Log Summary", {"payment_id": unique_id}
				):
					# format bank statement data
					if "CITI_IN_MT940" in self.name:
						data = {
							"unique_id": unique_id,
							"value_date": data.get("transaction_date"),
							"amount": data.get("transaction_amount"),
							"bank_ref_no": data.get("bank_reference"),
							"status_code": data.get("transaction_code"),
							"status": "Processed",
							"status_description": data.get("description"),
							"utr_number": data.get("bank_reference"),
						}
					frappe.db.set_value(
						"Payment Log Summary",
						log_summary,
						"status",
						json.dumps(data, indent=4),
					)

	@frappe.whitelist()
	def decrypt_file(self):
		if self.host and self.host_name:
			host = frappe.get_doc(self.host, self.host_name)
			if hasattr(host, "decrypt_file_content"):
				getattr(host, "decrypt_file_content")(self.name)

	@frappe.whitelist()
	def format_response(self):
		if self.host and self.host_name:
			host = frappe.get_doc(self.host, self.host_name)
			if hasattr(host, "format_response"):
				getattr(host, "format_response")(self.name, self.decrypted_data)

	def set_formated_response(self) -> str:
		host_doc = frappe.get_doc(self.host, self.host_name)

		if host_doc.encrypt_payment_file:
			try:
				if hasattr(host_doc, "decrypt_file_content"):
					decrypted_data = host_doc.decrypt_file_content(self.response)
					self.decrypted_data = decrypted_data
			except Exception:
				self.error = frappe.get_traceback(with_context=True)
		else:
			self.decrypted_data = self.response

		if self.decrypted_data:
			try:
				if hasattr(host_doc, "format_response"):
					host_doc.format_response(self.name, self.decrypted_data)
			except Exception:
				self.error = frappe.get_traceback(with_context=True)
