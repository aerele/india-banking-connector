import frappe
from frappe import _
from frappe.utils import cint


class ConnectorNotFoundError(Exception):
	pass

def check_connector(bank, bulk_transaction):
	filters = {
		"parent": "Connector Settings",
		"bank": bank,
	}
	if bulk_transaction:
		filters.update({"bulk_transaction": cint(bulk_transaction)})

	connector = frappe.get_value(
		"Connector Map",
		filters,
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
	if frappe.db.exists("DocType", connector):
		return connector

	frappe.throw(f"{connector} Not Found", ConnectorNotFoundError)


def get_connector(payload, bulk_transaction=None):
	doc = frappe._dict(payload.doc)
	connector_name = get_bank_connector(doc.company_bank)

	try:
		connector_filter = {
			"account_number": doc.company_account_number,
		}
		if frappe.get_meta(connector_name).has_field("bulk_payment"):
			connector_filter.update({"bulk_payment": bulk_transaction})

		connector_doc = frappe.get_doc(connector_name, connector_filter)
		connector_doc.bulk_transaction = bulk_transaction
		connector_doc.doc = doc
		connector_doc.payment_doc = payload
		return connector_doc

	except frappe.exceptions.DoesNotExistError:
		frappe.throw(
			title=_("Connection failed"),
			msg=_("Bank Connector not found for Account Number {0}").format(
				doc.company_account_number
			),
		)

	except Exception:
		return {"message": frappe.get_traceback()}
