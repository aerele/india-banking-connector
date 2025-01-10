import random
import re
import string

import frappe

from india_banking_connector.default import DEFAULT_CONNECTOR


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
