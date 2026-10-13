from india_banking_connector.install import create_connector_settings, create_default_bank


def execute():
	create_default_bank()
	create_connector_settings(update=True)
