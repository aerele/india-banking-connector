import frappe
import json
from india_banking_connector.connectors import get_connector

@frappe.whitelist()
def connect(**payload):
    if not payload:
        return "Payload is required"
    try:
        if isinstance(payload, str):
            payload = json.loads(payload)

        payload = frappe._dict(payload)

        connector = get_connector(payload.doc)
        response = connector.get_response(payload.method)

        return response

    except:
        frappe.log_error("Connector Error", frappe.get_traceback())
        return {'connector_status': 'failed', "message": frappe.get_traceback()}
    else:
        return response
