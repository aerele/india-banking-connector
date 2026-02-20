import json

import frappe


@frappe.whitelist()
def connect(**payload):
	"""
	Establish a connection to the banking connector based on the provided payload.

	:param payload: The payload to be processed.
	:return: The response from the connector.
	"""
	PV = PayloadValidator(payload)
	if PV.connector_status == "failed":
		return {"error": PV.error}

	try:
		settings = frappe.get_single("Connector Settings")
		connector = settings.get_connector(PV.data, payload.get("bulk_transaction"))

		if isinstance(connector, frappe.model.document.Document):
			return connector.get_response(PV.data.method)

		return connector
	except Exception as e:
		frappe.log_error("Connector Error", frappe.get_traceback(with_context=True))
		return {"status": "Request Failure", "message": str(e)}


class PayloadValidator:
	def __init__(self, payload: str | dict) -> None:
		self.connector_status = None
		self.error = None
		self.data = None

		self.validate_payload_params(payload)

	def validate_payload_params(self, payload):
		if not payload:
			self.error = (
				"Invalid request parameters. Please verify the payload and try again."
			)

			self.connector_status = "failed"
			return

		try:
			self.data = (
				frappe._dict(json.loads(payload))
				if isinstance(payload, str)
				else frappe._dict(payload)
			)
		except Exception:
			frappe.log_error(
				"Failed to load Payload", frappe.get_traceback(with_context=True)
			)
			self.error = (
				"Invalid request parameters. Please verify the payload and try again."
			)
			self.connector_status = "failed"
