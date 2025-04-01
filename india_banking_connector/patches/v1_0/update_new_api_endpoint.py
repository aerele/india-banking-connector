import click
import frappe

from india_banking_connector.install import create_bank_api_endpoint


def execute():
	click.secho("* Updating API Endpoints")
	frappe.db.delete("Bank API Endpoint")
	frappe.db.delete("Endpoint URLs")

	create_bank_api_endpoint()
