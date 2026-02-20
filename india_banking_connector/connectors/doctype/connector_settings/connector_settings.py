# Copyright (c) 2024, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

import frappe
from frappe import _
from frappe.model.document import Document


class ConnectorNotFoundError(Exception):
	pass


class ConnectorSettings(Document):
	def get_connector(self, payload: (str | dict), bulk_transaction) -> str:
		"""
		Get the connector based on the bank in the payload.

		:param self: Description
		:param payload: Description
		:type payload: (str | dict)
		:return: Description
		:rtype: str
		"""
		doc = frappe._dict(payload.doc)
		connector = self.get_bank_connector(
			doc.company_bank, integration_mode=payload.integration_mode
		)
		try:
			connector_filter = {
				"account_number": doc.company_account_number,
			}

			if frappe.get_meta(connector).has_field("bulk_payment"):
				connector_filter.update({"bulk_payment": bulk_transaction})

			connector_doc = frappe.get_doc(connector, connector_filter)
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
				exc=ConnectorNotFoundError,
			)

		except Exception as e:
			frappe.throw(
				title=_("Connection failed"),
				msg=str(e),
			)

	def get_bank_connector(self, bank: str, integration_mode: str = None):
		connector = self.check_connector(bank, integration_mode)
		if frappe.db.exists("DocType", connector):
			return connector

		frappe.throw(
			_("{connector} Not Found").format(connector=connector),
			ConnectorNotFoundError,
		)

	def check_connector(self, bank: str, integration_mode: str = None):
		"""
		Find the connector mapped for the bank in the connector settings.
		"""
		filters = {
			"parent": "Connector Settings",
			"bank": bank,
		}

		# Select connector map based on integration mode
		connector_map = "Connector Map"
		connector_field_map = "connector"
		if integration_mode == "H2H":
			connector_map = "H2H Connector Map"
			connector_field_map = "host"

		connector = frappe.get_value(
			connector_map,
			filters,
			connector_field_map,
		)

		if not connector:
			frappe.throw(
				_(
					"There is no connector map in the connector settings for Bank {bank}"
				).format(bank=bank),
				title=_("Connection failed"),
			)

		return connector
