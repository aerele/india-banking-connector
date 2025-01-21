import click
import frappe

from india_banking_connector.default import (
	BANKS_CONNECTOR_MAP,
	BULK_TRANSACTION_ENABLED_BANK,
	ENCRYPTED_END_POINTS,
	STD_BANK_LIST,
)
from india_banking_connector.utils import decrypt


def after_install():
	click.secho("* Updating India Banking Connector Customisations")
	create_default_bank()
	create_connector_settings()
	create_bank_doctype()


def create_default_bank():
	click.echo(" -> Creating Default Banks")
	for bank in STD_BANK_LIST:
		if not frappe.db.exists("Bank", bank):
			bank_doc = frappe.new_doc("Bank")
			bank_doc.bank_name = bank
			bank_doc.is_standard = 1
			bank_doc.save()


def create_connector_settings():
	click.echo(" -> Updating Connector Settings")
	settings_doc = frappe.get_doc("Connector Settings")
	connector_map = [
		{
			"bank": bank,
			"connector": connector,
			"bulk_transaction": 1 if bank in BULK_TRANSACTION_ENABLED_BANK else 0,
		}
		for bank, connector in BANKS_CONNECTOR_MAP.items()
		if not frappe.db.exists(
			"Connector Map",
			{
				"bank": bank,
				"connector": connector,
				"bulk_transaction": 1 if bank in BULK_TRANSACTION_ENABLED_BANK else 0,
			},
		)
	]
	if connector_map:
		settings_doc.extend("connectors", connector_map)
		settings_doc.save()


def create_bank_doctype():
	if "erpnext" not in frappe.get_installed_apps() and not frappe.db.exists(
		"DocType", "Bank"
	):
		click.echo(" -> Creating Bank Doctype")
		doc = {
			"doctype": "DocType",
			"name": "Bank",
			"module": "India Banking Connector",
			"is_submittable": 0,
			"istable": 0,
			"editable_grid": 0,
			"issingle": 0,
			"is_tree": 0,
			"custom": 1,
			"permissions": [
				{
					"create": 1,
					"delete": 1,
					"email": 1,
					"export": 1,
					"print": 1,
					"read": 1,
					"report": 1,
					"role": "System Manager",
					"share": 1,
					"write": 1,
					"submit": 0,
				}
			],
			"fields": [
				{"fieldtype": "Section Break"},
				{
					"label": "Bank Name",
					"fieldname": "bank_name",
					"fieldtype": "Data",
				},
			],
		}
		frappe.call("frappe.client.insert", doc=doc)


def create_bank_api_endpoint():
	def _create_endpoint_list(urls, **kwargs):
		doc = frappe.new_doc("Bank API Endpoint")
		doc.update(kwargs)
		doc.extend(
			"end_points",
			[{"action": action, "url": url} for action, url in urls.items()],
		)
		doc.insert(ignore_permissions=True)

	decrypted_endpoints = decrypt(ENCRYPTED_END_POINTS)

	for bank, api_detais in decrypted_endpoints.items():
		bank = bank.replace("_", " ")
		api_detais = frappe._dict(api_detais)
		if api_detais.production:
			if production_composite := frappe._dict(
				api_detais.production.get("composite", {})
			):
				print(production_composite)
				filters = {
					"bank": bank,
					"environment": "Production",
					"bulk_transaction": 0,
				}
				if not frappe.db.exists("Bank API Endpoint", filters):
					_create_endpoint_list(production_composite, **filters)
			if production_bulk := frappe._dict(api_detais.production.get("bulk", {})):
				filters = {
					"bank": bank,
					"environment": "Production",
					"bulk_transaction": 1,
				}
				if not frappe.db.exists("Bank API Endpoint", filters):
					_create_endpoint_list(production_bulk, **filters)
		if api_detais.testing:
			if testing_composite := frappe._dict(
				api_detais.testing.get("composite", {})
			):
				filters = {
					"bank": bank,
					"environment": "Testing",
					"bulk_transaction": 0,
				}
				if not frappe.db.exists("Bank API Endpoint", filters):
					_create_endpoint_list(testing_composite, **filters)
			if testing_bulk := frappe._dict(api_detais.testing.get("composite", {})):
				filters = {
					"bank": bank,
					"environment": "Testing",
					"bulk_transaction": 1,
				}
				if not frappe.db.exists("Bank API Endpoint", filters):
					_create_endpoint_list(testing_bulk, **filters)
