import base64
import json
import random
import re
import string

import frappe
from cryptography.fernet import Fernet

from india_banking_connector.default import DEFAULT_CONNECTOR

HASH_KEY = "india_banking_connector"


@frappe.whitelist()
def get_default_connectors():
	return DEFAULT_CONNECTOR


def get_id(length: int = 10, text: str = "") -> str:
	"""
	Generate a random string ID of a specified length, optionally prefixed with a given text.
	If the `length` parameter is a string, it will be used as the prefix text, and the length of the generated ID will be equal to the length of this string.
	Args:
	        length (int): The desired length of the generated ID. Defaults to 10.
	        text (str): An optional prefix text to include in the generated ID. Defaults to an empty string.
	Returns:
	        str: A randomly generated string ID of the specified length, optionally prefixed with the given text.
	"""

	if isinstance(length, str):
		text = length
		length = len(length)
		return text + "".join(
			random.choices(string.ascii_lowercase + string.digits, k=length)
		)
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
	def __init__(self, text, status_code):
		self.text = text
		self.status_code = status_code
		self.ok = 200 <= status_code < 300

	def json(self):
		try:
			return json.loads(self.text)
		except Exception:
			return frappe.get_traceback(with_context=True)
