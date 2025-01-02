import click
import frappe

from india_banking_connector.default import (
	BANKS_CONNECTOR_MAP,
	BULK_TRANSACTION_ENABLED_BANK,
	STD_BANK_LIST,
)


def after_install():
	click.secho("* Updating India Banking Connector Customisations")
	create_default_bank()
	create_connector_settings()


def create_default_bank():
	click.secho("* Creating Default Banks")
	for bank in STD_BANK_LIST:
		if not frappe.db.exists("Bank", bank):
			bank_doc = frappe.new_doc("Bank")
			bank_doc.bank_name = bank
			bank_doc.is_standard = 1
			bank_doc.save()


def create_connector_settings():
	click.echo("* Updating Connector Settings")
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
