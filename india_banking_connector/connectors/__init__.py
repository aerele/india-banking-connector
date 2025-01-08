import importlib

import frappe
from frappe import _, scrub
from frappe.utils import cint, cstr


def import_connector(connector_path, connector_name):
	module = importlib.import_module(connector_path)
	return getattr(module, connector_name)


def check_connector(bank, bulk_transaction):
	connector = frappe.get_value(
		"Connector Map",
		{
			"parent": "Connector Settings",
			"bank": bank,
			"bulk_transaction": cint(bulk_transaction),
		},
		"connector",
	)
	if not connector:
		frappe.throw(
			_("There is no connector map in the connector settings."),
			title=_("Connection failed"),
		)

	return connector


def get_bank_connector(bank, bulk_transaction=False):
	connector = check_connector(bank, bulk_transaction)
	path = f"{scrub(connector)}.{scrub(connector)}"
	connector_path = f"india_banking_connector.connectors.doctype.{path}"

	try:
		return import_connector(connector_path, connector.replace(" ", "")), connector
	except ImportError:
		frappe.log_error(
			_("Connector not found for bank {bank}").format(bank=bank),
			frappe.get_traceback(with_context=True),
		)

		frappe.throw(_("Not Implemented"), title=_("Connection failed"))


def get_connector(payload, bulk_transaction=None):
	doc = frappe._dict(payload.doc)
	BankConnector, connector_name = get_bank_connector(doc.company_bank)

	class Connector(BankConnector):
		def __init__(self, *args, **kwargs):
			super().__init__(*args, **kwargs)
			self.is_active()

		def get_response(self, method):
			if method and hasattr(self, method):
				return getattr(self, method)()
			else:
				return self.as_dict(), cstr(method), _("Invalid Method")

	try:
		return Connector(
			connector_name,
			doc.company_account_number,
			bulk_transaction=bulk_transaction,
			doc=doc,
			payment_doc=payload,
		)
	except frappe.exceptions.DoesNotExistError:
		frappe.throw(
			title=_("Connection failed"),
			msg=_("Bank Connector not found for Account Number {0}").format(
				doc.company_account_number
			),
		)

	except Exception:
		return {"message": frappe.get_traceback()}
