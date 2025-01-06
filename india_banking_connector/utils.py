import random
import re
import string

import frappe

from india_banking_connector.default import DEFAULT_CONNECTOR


@frappe.whitelist()
def get_default_connectors():
	return DEFAULT_CONNECTOR


def get_id(length: int = 10, text: str = "") -> str:
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
