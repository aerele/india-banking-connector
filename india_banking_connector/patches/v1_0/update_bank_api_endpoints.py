import click

from india_banking_connector.install import create_bank_api_endpoint


def execute():
	click.secho("* Updating Bank API Endpoints", fg="green")
	create_bank_api_endpoint()
