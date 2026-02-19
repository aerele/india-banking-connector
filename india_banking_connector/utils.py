import base64
import json
import random
import re
import string

import frappe
from cryptography.fernet import Fernet
from frappe.model.document import Document
from frappe.utils import cint

from india_banking_connector.default import DEFAULT_CONNECTOR, DEFAULT_HOSTS

HASH_KEY = "india_banking_connector"


@frappe.whitelist()
def get_default_connectors():
	return DEFAULT_CONNECTOR


@frappe.whitelist()
def get_default_hosts():
	return DEFAULT_HOSTS


def get_id(length: int = 10, text: str = "") -> str:
	"""
	Generate a random string ID of a specified length, optionally prefixed with a given text.
	If the `length` parameter is a string, it will be used as the prefix text, and
	the length of the generated ID will be equal to the length of this string.
	Args:
	        length (int): The desired length of the generated ID. Defaults to 10.
	        text (str): An optional prefix text to include in the generated ID. Defaults to an empty string.
	Returns:
	        str: A randomly generated string ID of the specified length, optionally prefixed with the given text.
	"""

	if isinstance(length, str):
		text = "".join(re.findall(r"[0-9a-zA-Z]", length))
		return text

	elif isinstance(length, int):
		text = "".join(re.findall(r"[0-9a-zA-Z]", text))
		text_length = len(text)
		if text_length >= length:
			return text[:length]
		else:
			length = length - text_length
			return text + "".join(
				random.choices(string.ascii_lowercase + string.digits, k=length)
			)


def encrypt(data, key=None):
	if not key:
		key = HASH_KEY

	key = key.ljust(32)[:32].encode("utf-8")

	key = base64.urlsafe_b64encode(key)

	cipher = Fernet(key)

	json_data = json.dumps(data).encode("utf-8")
	encrypted_data = cipher.encrypt(json_data)
	return encrypted_data


def decrypt(data, key=None):
	if not key:
		key = HASH_KEY

	key = key.ljust(32)[:32].encode("utf-8")

	key = base64.urlsafe_b64encode(key)

	cipher = Fernet(key)

	decrypted_data = cipher.decrypt(data)
	try:
		return json.loads(decrypted_data.decode("utf-8"))
	except Exception:
		return decrypted_data.decode("utf-8")


class ResponseObject:
	def __init__(
		self, text, status_code, method="POST", url=None, headers=None, body=None
	):
		self.text = text
		self.status_code = cint(status_code)
		self.ok = self.status_code == 200
		self.validate_json_text()

	@property
	def request(self):
		return frappe._dict(
			{
				"method": self.get("method", ""),
				"url": self.get("url", ""),
				"headers": self.get("headers", ""),
				"body": self.get("body", ""),
			}
		)

	def json(self):
		try:
			if isinstance(self.text, dict):
				return self.text
			return json.loads(self.text)
		except Exception:
			frappe.log_error(
				"Response Object ERROR:", frappe.get_traceback(with_context=1)
			)
			try:
				# Convert JSON string
				text = self.text.replace("'", '"')
				json_text = json.loads(text)
				# update valid JSON String
				if json_text:
					self.text = text

				# return valid dict
				return json_text
			except Exception:
				return frappe.get_traceback(with_context=True)

	def validate_json_text(self):
		self.json()


def get_existing_doc(doctype: str, filters: dict = None) -> Document | None:
	"""
	Retrieve an existing document object from the database based on the specified filters or document name.

	Args:
	        doctype (str): The name of the DocType to search for.
	        filters (dict): A dictionary of filters to apply when searching for the document. Defaults to None.

	Returns:
	        Document | None: The document object if found, otherwise None.
	"""
	if isinstance(filters, str):
		filters = {"name": filters}
	if filters:
		doc = frappe.get_all(doctype, filters=filters, limit_page_length=1)
		return frappe.get_doc(doctype, doc[0].name) if doc else None
	return None
