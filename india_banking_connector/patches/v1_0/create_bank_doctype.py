from india_banking_connector.install import create_bank_doctype, create_default_bank


def execute():
	create_bank_doctype()
	create_default_bank()
