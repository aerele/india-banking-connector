import frappe
import importlib
from frappe.utils import cint, cstr
from frappe import scrub
from india_banking_connector.utils import DEFAULT_CONNECTOR

def import_connector(connector_path, connector_name):
    module = importlib.import_module(connector_path)
    return getattr(module, connector_name)

def get_bank_connector(bank, bulk_transaction=False):
    connector = frappe.get_value("Connector Map", {"parent": "Connector Settings", "bank": bank, "bulk_transaction": cint(bulk_transaction)}, "connector")
    try:
        connector_path = "india_banking_connector.connectors.doctype"+ "."+scrub(connector) + "."+ scrub(connector)
        return import_connector(connector_path, connector.replace(" ", "")), connector

    except:
        frappe.log_error("Connector not found for bank {bank}", frappe.get_traceback())

    return "Not Implemented"

def get_connector(doc):
    doc = frappe._dict(doc)

    BankConnector, connector_name = get_bank_connector(doc.company_bank)

    class Connector(BankConnector):
        def get_response(self, method):
            if method and hasattr(self, method):
                return getattr(self, method)()
            else:
                return self.as_dict(), cstr(method) , "Invalid Method"

    return Connector(connector_name, doc.company_account_number)