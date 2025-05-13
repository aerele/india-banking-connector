import json

import frappe

from india_banking_connector.connectors import get_connector


@frappe.whitelist()
def connect(**kwargs):
	if not kwargs:
		return None

	payload = (
		frappe._dict(json.loads(kwargs))
		if isinstance(kwargs, str)
		else frappe._dict(kwargs)
	)

	try:
		connector = get_connector(payload, payload.bulk_transaction)

		if isinstance(connector, frappe.model.document.Document):
			return connector.get_response(payload.method)
		else:
			return connector

	except:
		frappe.log_error("Connector Error", frappe.get_traceback(with_context=True))
		return {"status": "Request Failure", "error": "Connector Error: please check log and try again", "traceback": frappe.get_traceback()}
