# Copyright (c) 2025, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

import frappe
import jwt
import requests
from frappe import _
from frappe.query_builder import DocType

from india_banking_connector.connectors.bank_connector import BankConnector
from india_banking_connector.india_banking_connector.doctype.bank_request_log.bank_request_log import (
	create_api_log,
)


class IDFCConnector(BankConnector):
	__all__ = [
		"initiate_payment",
		"get_payment_status",
	]

	def __init__(self, *args, **kwargs):
		self.bank = "IDFC"
		super().__init__(*args, **kwargs)

	@property
	def urls(self):
		CONNECTOR = DocType(self.doctype)
		EU = DocType("Endpoint URLs")
		urls = (
			frappe.qb.from_(CONNECTOR)
			.join(EU)
			.on(EU.parent == self.name)
			.select(EU.action, EU.url)
			.orderby(EU.idx)
		).run()

		return frappe._dict(dict(urls))

	def get_oauth_token(self):
		headers = {
			"Accept": "application/json",
			"Content-Type": "application/x-www-form-urlencoded",
		}

		data = {
			"grant_type": "client_credentials",
			"scope": self.scope,
			"client_id": self.client_id,
			"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			"client_assertion": self.get_client_assertion(),
		}

		try:
			response = requests.post(
				self.urls.oauth_token,
				headers=headers,
				data=data,
			)

			create_api_log(response, action="Get OAuth Token")

			if response.ok:
				return response.json().get("access_token")
		except Exception:
			frappe.log_error("Oauth Failed", frappe.get_traceback(with_context=True))
			frappe.throw(
				_(
					"Connection failed. Unable to authenticate with the connector. Please verify your credentials"
				)
			)

	def get_client_assertion(self):
		headers = {
			"alg": "RS256",
			"typ": "JWT",
			"kid": self.get_password("signing_key"),
		}
		payload = {
			"jti": frappe.generate_hash(length=30),
			"sub": self.client_id,
			"iss": self.client_id,
			"aud": self.urls.get("oauth_token"),
			"exp": 600,  # 10 minutes
		}

		return jwt.encode(
			payload,
			self.get_file_content(self.private_key),
			algorithm="RS256",
			headers=headers,
		)

	@frappe.whitelist()
	def get_api_endpoints(self):
		from india_banking_connector.default import IDFC_ENCRYPTED_END_POINTS
		from india_banking_connector.install import decrypt

		decrypted = decrypt(IDFC_ENCRYPTED_END_POINTS)
		print(decrypted)
		stagin_or_prod = "testing" if self.testing else "production"
		endpoints = decrypted[self.bank][stagin_or_prod]["composite"]

		self.api_endpoints = []
		self.extend(
			"api_endpoints",
			[{"action": action, "url": url} for action, url in endpoints.items()],
		)
