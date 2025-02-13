import frappe

from india_banking_connector.install import create_bank_doctype


def execute():
	create_bank_doctype()
