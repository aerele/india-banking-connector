import frappe
import json
from india_banking_connector.connectors import get_connector

@frappe.whitelist()
def connect(**kwargs):
	if not kwargs: return None

	if isinstance(kwargs, str):
		payload = frappe._dict(json.loads(kwargs))
	else:
		payload = frappe._dict(kwargs)

	try:
		connector = get_connector(payload, payload.bulk_transaction)

		if isinstance(connector, frappe.model.document.Document):
			response = connector.get_response(payload.method)
		else:
			return connector

		return response

	except:
		frappe.log_error("Connector Error", frappe.get_traceback())
		return {'connector_status': 'failed', "message": frappe.get_traceback()}
