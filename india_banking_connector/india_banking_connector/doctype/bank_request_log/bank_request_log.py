# Copyright (c) 2024, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

import frappe
import json
from frappe.model.document import Document
from requests.models import Response
from frappe.utils import cstr
class BankRequestLog(Document):
	pass

@frappe.whitelist()
def create_api_log(res, action= None, account_config = None, ref_doctype= None, ref_docname= None):
	"""Can create API log From response

	Args:
		res (response object): It is used to obtain an API response.
		request_from (str): It is optional for the purposes of the API...
	"""
	if not isinstance(res, Response): return

	try:
		log_doc = frappe.new_doc("Bank Request Log")
		log_doc.action = action
		log_doc.config_details = json.dumps(account_config, indent=4)
		log_doc.url = res.request.url
		log_doc.payload = cstr(res.request.body)
		log_doc.method =  res.request.method
		log_doc.header = json.dumps(dict(res.request.headers), indent=4)
		log_doc.response = json.dumps(res.text, indent=4)
		log_doc.status_code = res.status_code
		log_doc.reference_doctype = ref_doctype
		log_doc.reference_docname = ref_docname
		log_doc.document_hash = get_log_hash(log_doc)
		log_doc.save()
	except:
		frappe.log_error(title='Error in creating API Log', message=frappe.get_traceback(with_context=True))
	else:
		frappe.db.commit()
		return log_doc.name


def get_log_hash(log_doc=None):
	if not log_doc:
		return ""
	from frappe.core.doctype.file.file import get_content_hash
	try:
		request_details = {
			"action": log_doc.get("action", ""),
			"config_details": log_doc.get("config_details", ""),
			"status_code": log_doc.get("status_code", ""),
			"url": log_doc.get("url", ""),
			"reference_doctype": log_doc.get("reference_doctype", ""),
			"reference_docname": log_doc.get("reference_docname", ""),
			"decrypted_response": log_doc.get("decrypted_response", "")
		}

		request_details = json.dumps(request_details)
		return get_content_hash(request_details)
	except Exception:
		frappe.log_error(title="Error Generating Content Hash", message=frappe.get_traceback(with_context=True))
		return ""
