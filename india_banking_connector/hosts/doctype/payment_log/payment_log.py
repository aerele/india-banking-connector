# Copyright (c) 2026, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

import json

import frappe
from frappe.model.document import Document


class PaymentLog(Document):
	def get_summary_details(self, action=None):
		"""
		summarize the payment log.
		Returns:
		    dict: A dictionary containing the formatted response of the payment log.
		"""
		res_dict = frappe._dict()

		if self.status == "Pending Upload":
			res_dict.payment_status = "Pending Upload"
			res_dict.message = "Payment is pending upload"
			res_dict.summary_details = {}
		elif self.status == "Uploaded":
			res_dict.payment_status = (
				"PROCESSED" if action == "get_payment_status" else "ACCEPTED"
			)

			res_dict.summary_details = {
				sd.payment_id: json.loads(sd.status) or {}
				for sd in self.payment_summary
			}
		else:
			res_dict.message = "Unknown status"

		return res_dict

	@frappe.whitelist()
	def decrypt_file(self):
		return frappe.get_doc(self.host, self.host_name).decrypt_file(
			encrypted_file=self.encrypted_file,
		)

	@frappe.whitelist()
	def get_encrypt_payment_file(self):
		host = frappe.get_doc(self.host, self.host_name)
		return host.get_encrypt_payment_file(self.name)
