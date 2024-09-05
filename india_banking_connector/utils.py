import frappe

DEFAULT_CONNECTOR = ['ICICI Connector']

@frappe.whitelist()
def get_default_connectors():
    return DEFAULT_CONNECTOR