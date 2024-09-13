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

        print("============================payload======================================")
        print(payload)
        print("============================payload======================================")


        connector = get_connector(payload.doc, payload.bulk_transaction)

        print(connector, "==============connector========================")

        if isinstance(connector, frappe.model.document.Document):
            response = connector.get_response(payload.method)
        else:
            return connector
            response = connector.message

        return response

    except:
        frappe.log_error("Connector Error", frappe.get_traceback())
        return {'connector_status': 'failed', "message": frappe.get_traceback()}
    else:
        return response
