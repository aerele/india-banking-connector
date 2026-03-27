from urllib.parse import urlparse

import frappe
from frappe.query_builder import DocType

from india_banking_connector.default import BANKS_CONNECTOR_MAP


def execute():
	for bank, connector_doc in BANKS_CONNECTOR_MAP.items():
		EndpointURLs = DocType("Endpoint URLs")
		BankAPIEndpoint = DocType("Bank API Endpoint")

		urls = (
			frappe.qb.from_(EndpointURLs)
			.join(BankAPIEndpoint)
			.on(EndpointURLs.parent == BankAPIEndpoint.name)
			.select(EndpointURLs.action, EndpointURLs.url)
			.where(
				(EndpointURLs.parenttype == "Bank API Endpoint")
				& (EndpointURLs.parentfield == "end_points")
				& (BankAPIEndpoint.bank == bank)
				& (BankAPIEndpoint.bulk_transaction == 0)
				& (BankAPIEndpoint.environment == "Production")
			)
		).run(as_dict=True)

		if not urls:
			continue

		connectors = frappe.get_all(connector_doc, {"active": 1}, pluck="name")
		for connector in connectors:
			try:
				doc = frappe.get_doc(connector_doc, connector)
				if doc.api_endpoints:
					continue
				make_payment_url = next(
					i["url"] for i in urls if i["action"] == "make_payment"
				)
				parsed = urlparse(make_payment_url)
				base_url = f"{parsed.scheme}://{parsed.netloc}"
				doc.base_url = base_url
				doc.api_endpoints = []
				doc.extend(
					"api_endpoints",
					urls,
				)
				doc.save()
				frappe.db.commit()
			except Exception:
				frappe.db.rollback()
				frappe.log_error(
					"Update Endpoints patch Failed",
					frappe.get_traceback(with_context=1),
				)
