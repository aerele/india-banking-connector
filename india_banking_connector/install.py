import click
import frappe
from frappe.custom.doctype.custom_field.custom_field import create_custom_fields

from india_banking_connector.default import (
	BANKS_CONNECTOR_MAP,
	BANKS_H2H_MAP,
	BULK_TRANSACTION_ENABLED_BANK,
	STD_BANK_LIST,
)


def after_install():
	click.secho("* Updating India Banking Connector Customisations")
	create_bank_doctype()
	create_default_bank()
	create_connector_settings()
	create_bank_account_beneficiary_fields()


def create_bank_account_beneficiary_fields():
	click.echo(" -> Installing IndusInd Beneficiary Fields in Bank Account")
	create_custom_fields(
		{
			"Bank Account": [
				{
					"label": "IndusInd Beneficiary Details",
					"fieldname": "indusind_beneficiary_section",
					"fieldtype": "Section Break",
					"insert_after": "bank_account_no",
					"collapsible": 1,
				},
				{
					"label": "Beneficiary Code",
					"fieldname": "indusind_ben_code",
					"fieldtype": "Data",
					"read_only": 1,
					"no_copy": 1,
					"insert_after": "indusind_beneficiary_section",
				},
				{
					"label": "Beneficiary Status",
					"fieldname": "indusind_beneficiary_status",
					"fieldtype": "Select",
					"options": "\nNot Registered\nPending\nActive\nInactive\nRejected\nFailed",
					"read_only": 1,
					"no_copy": 1,
					"insert_after": "indusind_ben_code",
				},
				{
					"label": "",
					"fieldname": "indusind_beneficiary_column_break",
					"fieldtype": "Column Break",
					"insert_after": "indusind_beneficiary_status",
				},
				{
					"label": "Beneficiary Batch ID",
					"fieldname": "indusind_beneficiary_batch_id",
					"fieldtype": "Data",
					"read_only": 1,
					"no_copy": 1,
					"hidden": 1,
					"insert_after": "indusind_beneficiary_column_break",
				},
				{
					"label": "Beneficiary Message",
					"fieldname": "indusind_beneficiary_message",
					"fieldtype": "Small Text",
					"read_only": 1,
					"no_copy": 1,
					"insert_after": "indusind_beneficiary_batch_id",
				},
			],
		}
	)


def create_default_bank():
	click.echo(" -> Creating Default Banks")
	for bank in STD_BANK_LIST:
		if not frappe.db.exists("Bank", bank):
			bank_doc = frappe.new_doc("Bank")
			bank_doc.bank_name = bank
			bank_doc.is_standard = 1
			bank_doc.save()


def create_connector_settings(update=False):
	click.echo(" -> Updating Connector Settings")
	settings_doc = frappe.get_doc("Connector Settings")

	for bank, connector in BANKS_CONNECTOR_MAP.items():
		if frappe.db.exists(
			"Connector Map",
			{
				"bank": bank,
				"connector": connector,
				"bulk_transaction": 1 if bank in BULK_TRANSACTION_ENABLED_BANK else 0,
			},
		):
			continue

		settings_doc.append(
			"connectors",
			{
				"bank": bank,
				"connector": connector,
				"bulk_transaction": 1 if bank in BULK_TRANSACTION_ENABLED_BANK else 0,
			},
		)
	for bank, host in BANKS_H2H_MAP.items():
		if not frappe.db.exists(
			"H2H Connector Map",
			{
				"bank": bank,
				"host": host,
			},
		):
			settings_doc.append(
				"hosts",
				{
					"bank": bank,
					"host": host,
				},
			)
	if update:
		settings_doc.flags.ignore_links = True
		settings_doc.save()
		return

	settings_doc.insert(ignore_links=True)


def create_bank_doctype():
	if "erpnext" not in frappe.get_installed_apps() and not frappe.db.exists(
		"DocType", "Bank"
	):
		click.echo(" -> Creating Bank Doctype")
		doc = {
			"doctype": "DocType",
			"name": "Bank",
			"autoname": "field:bank_name",
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
