import click
import frappe

from india_banking_connector.install import create_connector_settings


def execute():
	click.echo("* Removing Connector Map... *")
	frappe.db.delete("Connector Map")
	create_connector_settings()
