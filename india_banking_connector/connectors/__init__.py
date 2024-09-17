import frappe
import importlib
from frappe.utils import cint, cstr
from frappe import scrub
from india_banking_connector.utils import DEFAULT_CONNECTOR

def import_connector(connector_path, connector_name):
	module = importlib.import_module(connector_path)
	return getattr(module, connector_name)

def get_bank_connector(bank, bulk_transaction=False):
	connector = frappe.get_value(
    	"Connector Map",
    	{
			"parent": "Connector Settings",
			"bank": bank,
			"bulk_transaction": cint(bulk_transaction)
		},
		"connector"
	)
	if not connector:
		frappe.throw("There is no connector map in the connector settings.")
	try:
		path = scrub(connector) + "."+ scrub(connector)
		connector_path = "india_banking_connector.connectors.doctype."+ path
		return import_connector(connector_path, connector.replace(" ", "")), connector

	except:
		frappe.log_error("Connector not found for bank {bank}", frappe.get_traceback())

	return "Not Implemented"

def get_connector(payload, bulk_transaction = None):
	doc = frappe._dict(payload.doc)

	BankConnector, connector_name = get_bank_connector(doc.company_bank)

	class Connector(BankConnector):
		def get_response(self, method):
			if method and hasattr(self, method):
				return getattr(self, method)()
			else:
				return self.as_dict(), cstr(method) , "Invalid Method"
	try:
		return Connector(
			connector_name,
			doc.company_account_number,
			bulk_transaction= bulk_transaction,
			doc= doc,
			payment_doc= payload
		)
	except frappe.exceptions.DoesNotExistError:
		return {
			"message": "Bank Connector not found for Account Number {0}".format(
					doc.company_account_number
				)
			}
	except:
		return {
			"message": frappe.get_traceback()
			}