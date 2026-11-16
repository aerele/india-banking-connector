# Copyright (c) 2024, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

import json
import re
from xml.dom.minidom import parseString

import frappe
from frappe.model.document import Document
from frappe.utils import cint, cstr
from requests.models import Response
from requests.structures import CaseInsensitiveDict

from india_banking_connector.utils import ResponseObject, decrypt, encrypt


class BankRequestLog(Document):
	action_map = {
		"Initiate Payment": "make_payment",
		"Get Payment Status": "payment_status",
		"Bank Balance": "bank_balance",
		"Bank Statement": "bank_statement",
	}

	@frappe.whitelist()
	def decrypt_log(self):
		return {
			"payload": self.decrypt_data(self.payload),
			"header": self.decrypt_data(self.header),
			"config_details": self.decrypt_data(self.config_details),
			"response": self.decrypt_data(self.response),
			"decrypted_response": self.decrypt_data(self.decrypted_response),
		}

	def decrypt_data(self, data):
		"""Decrypt the given data if it is encrypted."""
		try:
			data = decrypt(data)
		except Exception:
			pass
		if isinstance(data, dict):
			data = json.dumps(data, indent=4)

		return data

	@frappe.whitelist()
	def decrypt_and_set_response(self):
		if self.connector and self.connector_name:
			connector = frappe.get_doc(self.connector, self.connector_name)
			connector.get_decrypted_response(
				ResponseObject(
					self.decrypt_data(self.response), cint(self.status_code)
				),
				method=self.action_map.get(self.action),
				log_id=self.name,
			)

	@frappe.whitelist()
	def request_payment_status(self):
		"""Request a BoB status inquiry using this log's CMS reference."""
		self.reload()
		self.check_permission("write")

		if self.action != "Initiate Payment" or cint(self.status_code) != 200:
			frappe.throw(
				frappe._(
					"Payment status can only be requested from a successful initiation log."
				)
			)
		if self.connector != "Bank of Baroda Connector":
			frappe.throw(
				frappe._(
					"This action is currently available only for Bank of Baroda initiation logs."
				)
			)
		if (
			not self.unique_id
			or self.reference_doctype != "Payment Order"
			or not self.reference_docname
			or not self.connector_name
		):
			frappe.throw(
				frappe._("The initiation log is missing its Payment Order reference.")
			)

		if not frappe.has_permission("Payment Order", "read", self.reference_docname):
			frappe.throw(
				frappe._("Not permitted to read this Payment Order."),
				frappe.PermissionError,
			)

		try:
			response_data = self.decrypt_data(self.decrypted_response)
			if isinstance(response_data, str):
				response_data = json.loads(response_data)
		except (TypeError, ValueError):
			frappe.throw(frappe._("Could not read the decrypted initiation response."))

		if not isinstance(response_data, dict):
			frappe.throw(frappe._("Could not read the decrypted initiation response."))

		payment_response = (response_data or {}).get("paymentTxnResp") or {}
		if not isinstance(payment_response, dict):
			frappe.throw(
				frappe._("The initiation response has an invalid payment response format.")
			)
		cms_ref = payment_response.get("cmsRef")
		if not cms_ref:
			frappe.throw(
				frappe._(
					"The initiation response does not contain a CMS reference; "
					"no status request was sent."
				)
			)

		connector = frappe.get_doc(self.connector, self.connector_name)
		connector.is_active()
		connector.payment_doc = frappe._dict(
			{
				"name": self.unique_id,
				"parenttype": self.reference_doctype,
				"parent": self.reference_docname,
			}
		)
		result = connector.get_payment_status(cms_ref=cms_ref)

		if not getattr(connector, "last_payment_status_log_id", None):
			frappe.throw(
				frappe._("The bank status request did not create a Bank Request Log.")
			)

		return {
			"log_id": connector.last_payment_status_log_id,
			"cms_ref": cms_ref,
			"result": result,
		}

	@staticmethod
	def clear_old_logs(days=30):
		from frappe.query_builder import Interval
		from frappe.query_builder.functions import Now

		table = frappe.qb.DocType("Bank Request Log")
		frappe.db.delete(
			table, filters=(table.creation < (Now() - Interval(days=days)))
		)


def format_with_indent(data):
	"""
	Format the given data with indentation for better readability.

	Note:
	        - If the input is a dictionary or CaseInsensitiveDict, it is converted to a pretty-printed JSON string.
	        - If the input is a JSON string, it is parsed and then converted to a pretty-printed JSON string.
	        - If the input is an XML string, it is converted to a pretty-printed XML string.
	        - If formatting fails, the original data is returned and an error is logged.
	"""
	try:
		if not data:
			return ""
		elif isinstance(data, dict):
			return json.dumps(data, indent=4)
		elif isinstance(data, CaseInsensitiveDict):
			return json.dumps(dict(data), indent=4)
		elif (data := data.strip()) and data.startswith("{") and data.endswith("}"):
			return format_with_indent(json.loads(data or ""))
		elif re.compile(r"^\s*<[^>]+>").match(data):
			return parseString(data).toprettyxml(indent=" " * 4)
	except Exception:
		frappe.log_error(
			title="Error in formatting data",
			message=frappe.get_traceback(with_context=True),
		)
	return data


def encrypt_log(data, encrypt_data=False):
	if not encrypt_data:
		return data

	return encrypt(data)


@frappe.whitelist()
def create_api_log(
	res,
	action=None,
	account_config=None,
	ref_doctype=None,
	ref_docname=None,
	unique_id=None,
	connector=None,
):
	"""Can create API log From response

	Args:
	        res (response object): It is used to obtain an API response.
	        request_from (str): It is optional for the purposes of the API...
	"""
	if not isinstance(res, Response):
		return

	try:
		_encrypt = False
		if connector:
			_encrypt = frappe.db.exists(
				"Connector Map",
				{
					"connector": connector.doctype,
					"encrypt_log": 1,
				},
			)
		log_doc = frappe.new_doc("Bank Request Log")
		log_doc.action = action
		log_doc.url = res.request.url
		log_doc.payload = encrypt_log(cstr(res.request.body), _encrypt)
		log_doc.method = res.request.method
		log_doc.header = encrypt_log(format_with_indent(res.request.headers), _encrypt)
		log_doc.response = encrypt_log(format_with_indent(res.text), _encrypt)
		log_doc.config_details = encrypt_log(
			format_with_indent(account_config), _encrypt
		)
		log_doc.status_code = res.status_code
		log_doc.reference_doctype = ref_doctype
		log_doc.reference_docname = ref_docname
		log_doc.unique_id = unique_id
		log_doc.connector = (connector or {}).get("doctype")
		log_doc.connector_name = (connector or {}).get("name")
		log_doc.encrypted = 1 if _encrypt else 0
		log_doc.save()
	except Exception:
		frappe.log_error(
			title="Error in creating API Log",
			message=frappe.get_traceback(with_context=True),
		)
	else:
		frappe.db.commit()
		return log_doc.name
