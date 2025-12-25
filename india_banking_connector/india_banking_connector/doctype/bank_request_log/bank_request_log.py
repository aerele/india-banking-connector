# Copyright (c) 2024, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

import json
import re
from xml.dom.minidom import parseString

import frappe
from frappe.model.document import Document
from frappe.utils import cstr
from requests.models import Response
from requests.structures import CaseInsensitiveDict

from india_banking_connector.utils import decrypt, encrypt


class BankRequestLog(Document):
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
		try:
			return decrypt(data)
		except Exception:
			return data


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
			title="Error in formatting data", message=frappe.get_traceback()
		)
	return data


def encrypt_log(data, encrypt_data=False):
	if not encrypt_data:
		return data

	encrypt(data)


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
		log_doc.save()
	except Exception:
		frappe.log_error(
			title="Error in creating API Log", message=frappe.get_traceback()
		)
	else:
		frappe.db.commit()
		return log_doc.name
