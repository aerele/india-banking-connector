# Copyright (c) 2024, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

import json
from xml.dom.minidom import parseString

import frappe
from frappe.model.document import Document
from frappe.utils import cstr
from requests.models import Response
from requests.structures import CaseInsensitiveDict


class BankRequestLog(Document):
	pass


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
		if isinstance(data, dict):
			return json.dumps(data, indent=4)
		elif isinstance(data, CaseInsensitiveDict):
			return json.dumps(dict(data), indent=4)
		else:
			return format_with_indent(json.loads(data))
	except:
		try:
			return parseString(data).toprettyxml(indent=" " * 4)
		except:
			pass

		frappe.log_error(
			title="Error in formatting data", message=frappe.get_traceback()
		)
		return data


@frappe.whitelist()
def create_api_log(
	res, action=None, account_config=None, ref_doctype=None, ref_docname=None
):
	"""Can create API log From response

	Args:
			res (response object): It is used to obtain an API response.
			request_from (str): It is optional for the purposes of the API...
	"""
	if not isinstance(res, Response):
		return

	try:
		log_doc = frappe.new_doc("Bank Request Log")
		log_doc.action = action
		log_doc.url = res.request.url
		log_doc.payload = cstr(res.request.body)
		log_doc.method = res.request.method
		log_doc.header = format_with_indent(res.request.headers)
		log_doc.response = format_with_indent(res.text)
		log_doc.config_details = format_with_indent(account_config)
		log_doc.status_code = res.status_code
		log_doc.reference_doctype = ref_doctype
		log_doc.reference_docname = ref_docname
		log_doc.save()
	except:
		frappe.log_error(
			title="Error in creating API Log", message=frappe.get_traceback()
		)
	else:
		frappe.db.commit()
		return log_doc.name
