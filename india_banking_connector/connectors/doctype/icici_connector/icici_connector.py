# Copyright (c) 2024, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

import json
import re
from base64 import b64encode

import frappe
import requests
from frappe import _
from frappe.utils import cstr, flt, getdate, nowdate

from india_banking_connector.connectors.bank_connector import BankConnector
from india_banking_connector.india_banking_connector.doctype.bank_request_log.bank_request_log import (
	create_api_log,
	create_request_log,
	update_request_log,
)
from india_banking_connector.utils import get_id

# (connect, read) timeout on every outbound bank call — a no-timeout POST can hang a worker
# indefinitely when the bank is slow/down. Read is generous: a bank payment reply can be slow,
# and we would rather get a definitive answer than an ambiguous ReadTimeout.
BANK_HTTP_TIMEOUT = (15, 60)


def _is_pre_send_connection_failure(exc):
	"""True ONLY when a ``requests.ConnectionError`` proves the TCP connection was never
	established — so the request was provably never sent and it is safe to treat as
	"not submitted". Verified against requests 2.33.1 / urllib3 in this runtime:

	  * connection refused -> ConnectionError -> MaxRetryError -> NewConnectionError -> ConnectionRefusedError
	  * DNS failure        -> ConnectionError -> MaxRetryError -> NameResolutionError -> socket.gaierror
	  * POST-SEND drop     -> ConnectionError -> ProtocolError  -> RemoteDisconnected   (AMBIGUOUS)

	A ``urllib3.ProtocolError`` anywhere in the cause chain means the connection had already been
	established and bytes may have reached the bank (RemoteDisconnected / "Connection aborted" /
	ECONNRESET) -> return False (ambiguous). Only NewConnectionError / socket.gaierror /
	connect-time ConnectionRefusedError prove a pre-connection failure. Unknown/unclassifiable
	chains return False (money-safe default: never assume "not sent")."""
	import socket

	try:
		from urllib3.exceptions import NewConnectionError, ProtocolError
	except Exception:
		return False

	seen, chain, stack = set(), [], [exc]
	while stack:
		cur = stack.pop()
		if cur is None or id(cur) in seen:
			continue
		seen.add(id(cur))
		chain.append(cur)
		for arg in getattr(cur, "args", ()):
			if isinstance(arg, BaseException):
				stack.append(arg)
		stack.append(getattr(cur, "__cause__", None))
		stack.append(getattr(cur, "__context__", None))

	# A post-send drop surfaces as ProtocolError -> ambiguous, never "not submitted".
	if any(isinstance(c, ProtocolError) for c in chain):
		return False
	# Retry-history veto (defensive / future-proof): a non-empty retry history anywhere in the
	# chain means a PRIOR attempt was already made (bytes may have been sent on that earlier try),
	# so even a final NewConnectionError is not proof of pre-send. The attribute is absent by
	# default (requests mounts no retries) -> no veto. This guards against anyone mounting a
	# POST-retrying adapter that turns a swallowed post-send drop into a "pre-send"
	# NewConnectionError on a subsequent attempt.
	if any(getattr(c, "history", None) for c in chain):
		return False
	# Provably never connected -> never sent.
	return any(
		isinstance(c, (NewConnectionError, socket.gaierror, ConnectionRefusedError)) for c in chain
	)


class ICICIConnector(BankConnector):
	bank = "ICICI Bank"

	AES_KEY = "1234567887654321".encode("utf-8")
	IV = "0000000000000000".encode("utf-8")

	__all__ = ["initiate_payment", "get_payment_status"]

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		self.bulk_transaction = kwargs.get("bulk_transaction")
		self.doc = frappe._dict(kwargs.get("doc", {}))
		self.payment_doc = frappe._dict(kwargs.get("payment_doc", {}))

	def autoname(self):
		self.name = self.account_number
		if self.get("bulk_payment"):
			self.name = f"{self.account_number}^B"

	@property
	def urls(self):
		return super().urls

	def headers(self, mode_of_transfer=None, params=None):
		headers = {
			"accept": "*/*",
			"content-type": "text/plain",
			"apikey": self.client_key,
			"host": self.urls.host,
		}

		if self.bulk_transaction:
			headers.update(
				{
					"content-type": "application/json",
					"x-priority": self.get_priority(mode_of_transfer),
				}
			)
		if params:
			headers.update(params)

		return headers

	@frappe.whitelist()
	def register(self):
		self.bulk_transaction = False
		self.update_client_details("register")
		url = self.urls.register
		headers = self.headers()
		payload = self.get_encrypted_payload(method="register")

		response = requests.post(url, headers=headers, data=payload)

		log_id = create_api_log(
			response,
			action="Register",
			account_config=self.get_account_config("register"),
			ref_doctype=self.doc.doctype,
			ref_docname=self.doc.name,
			connector=self,
		)

		res = self.get_decrypted_response(response, method="register", log_id=log_id)
		if res.status == "success":
			self.db_set("registration_status", "Registered")
		frappe.msgprint(res.message or _("Registration Failed"))

	@frappe.whitelist()
	def registration_inquiry(self):
		self.bulk_transaction = False
		self.update_client_details("registration_status")
		url = self.urls.registration_status
		headers = self.headers()
		payload = self.get_encrypted_payload(method="registration_status")

		response = requests.post(url, headers=headers, data=payload)

		log_id = create_api_log(
			response,
			action="Registration Status",
			account_config=self.get_account_config("registration_status"),
			ref_doctype=self.doc.doctype,
			ref_docname=self.doc.name,
			connector=self,
		)

		res = self.get_decrypted_response(
			response, method="registration_status", log_id=log_id
		)
		if res.status == "success":
			self.db_set("registration_status", "Registered")

		frappe.msgprint(res.message or _("Registration Status Fetched Failed"))

	def _logged_post(
		self, action, url, headers, payload, ref_doctype=None, ref_docname=None, unique_id=None
	):
		"""LOG-FIRST-then-UPDATE outbound POST, so EVERY attempt is recorded in the Bank Request
		Log — even when the bank is unreachable and no HTTP response ever comes back.

		Returns a structured result the caller can act on unambiguously::

			{"outcome": "response",       "response": <Response>, "log_id": <name>}   # got a reply
			{"outcome": "not_submitted",  "response": None,       "log_id": <name>, "message": ...} # provably PRE-send (connect never established: ConnectTimeout, or a ConnectionError whose cause is NewConnectionError / DNS gaierror / connect-time ConnectionRefusedError) -> request was NEVER sent -> caller may safely fail
			{"outcome": "timeout",        "response": None,       "log_id": <name>, "message": ...} # AMBIGUOUS: read timeout, OR a POST-send connection drop (RemoteDisconnected / ProtocolError / ECONNRESET), OR any unclassifiable error -> the bank may already hold it -> caller MUST keep OPEN

		Distinguishing "not submitted" from "ambiguous" is money-critical: failing + re-paying an
		ambiguous outcome could double-pay. A bare ``ConnectionError`` is NOT proof the request was
		not sent — it also fires on a post-send drop after the bytes reached the bank — so only a
		provably pre-connection failure is treated as "not submitted".
		"""
		log_id = create_request_log(
			action=action,
			url=url,
			payload=payload,
			method="POST",
			account_config=self.get_account_config(self.action_map.get(action)),
			ref_doctype=ref_doctype,
			ref_docname=ref_docname,
			unique_id=unique_id,
			connector=self,
			status="Requested",
		)
		try:
			response = requests.post(
				url, headers=headers, data=payload, timeout=BANK_HTTP_TIMEOUT
			)
		except requests.exceptions.ReadTimeout as e:
			# Connected + request sent, but no reply -> the bank MAY have received it. AMBIGUOUS.
			update_request_log(log_id, status="Timeout", message=str(e))
			return {"outcome": "timeout", "response": None, "log_id": log_id, "message": str(e)}
		except requests.exceptions.ConnectTimeout as e:
			# The TCP connect did not complete within the connect timeout -> connection never
			# established -> the request was provably NEVER sent. Definitively NOT submitted.
			update_request_log(log_id, status="Failed", message=str(e))
			return {"outcome": "not_submitted", "response": None, "log_id": log_id, "message": str(e)}
		except requests.exceptions.ConnectionError as e:
			# A ConnectionError does NOT prove the request wasn't sent — it ALSO fires on a post-send
			# drop (RemoteDisconnected / ProtocolError / ECONNRESET) AFTER the bytes reached the bank.
			# Only treat it as NOT submitted when the cause chain proves the connection was never
			# established (NewConnectionError / DNS gaierror / connect-time ConnectionRefusedError);
			# otherwise it is AMBIGUOUS and the row must stay OPEN for the status poll to reconcile.
			if _is_pre_send_connection_failure(e):
				update_request_log(log_id, status="Failed", message=str(e))
				return {"outcome": "not_submitted", "response": None, "log_id": log_id, "message": str(e)}
			update_request_log(log_id, status="Timeout", message=str(e))
			return {"outcome": "timeout", "response": None, "log_id": log_id, "message": str(e)}
		except Exception as e:
			# Any other transport-layer error before a response -> treat as AMBIGUOUS (do not assume
			# it was not submitted); the caller keeps it OPEN rather than risk a double-pay.
			update_request_log(log_id, status="Timeout", message=str(e))
			return {"outcome": "timeout", "response": None, "log_id": log_id, "message": str(e)}
		else:
			update_request_log(log_id, status="Success", response=response)
			return {"outcome": "response", "response": response, "log_id": log_id}

	# Maps the human "action" label to the get_account_config method key.
	action_map = {
		"Initiate Payment": "make_payment",
		"Payment Status": "payment_status",
	}

	def initiate_payment(self):
		self.update_client_details("make_payment")
		payment_details = self.payment_doc if not self.bulk_transaction else self.doc
		unique_id = "".join(re.findall(r"[0-9a-zA-Z]", payment_details.name))[-10:]
		if not self.bulk_transaction:
			unique_id = payment_details.name

		if existing_payment_response := self.validate_duplicate_payments(
			unique_id=unique_id
		):
			return existing_payment_response

		url = self.urls.make_payment
		headers = self.headers(payment_details.mode_of_transfer)
		payload = self.get_encrypted_payload(method="make_payment")

		result = self._logged_post(
			action="Initiate Payment",
			url=url,
			headers=headers,
			payload=payload,
			ref_doctype=payment_details.parenttype or payment_details.doctype,
			ref_docname=payment_details.parent or payment_details.name,
			unique_id=unique_id,
		)

		if result["outcome"] == "response":
			res = self.get_decrypted_response(
				result["response"], method="make_payment", log_id=result["log_id"]
			)
			# Explicit: a real reply was received. Consumers key on payment_status as before.
			res["submitted"] = True
			return res

		if result["outcome"] == "not_submitted":
			# DEFINITIVE: the bank was never reached, so the payment was NOT submitted. A distinct,
			# non-ambiguous signal so the consumer can safely mark the row Failed (no double-pay).
			return frappe._dict(
				{
					"payment_status": "Not Submitted",
					"submitted": False,
					"message": result.get("message")
					or "Bank not reachable — payment was not submitted.",
				}
			)

		# outcome == "timeout": AMBIGUOUS. Keep the legacy "Request Failure" payment_status for
		# backward-compat (existing consumers already treat it as still-open), but add submitted
		# = "unknown" so a consumer that understands it keeps the row OPEN rather than failing it.
		return frappe._dict(
			{
				"payment_status": "Request Failure",
				"submitted": "unknown",
				"message": result.get("message")
				or "No response from the bank (timeout) — payment status unknown.",
			}
		)

	def get_payment_status(self):
		self.update_client_details("payment_status")
		payment_details = self.payment_doc if not self.bulk_transaction else self.doc
		unique_id = "".join(re.findall(r"[0-9a-zA-Z]", payment_details.name))[-10:]
		if not self.bulk_transaction:
			unique_id = payment_details.name

		mode_of_transfer = payment_details.mode_of_transfer

		url = self.urls.payment_status
		headers = self.headers(mode_of_transfer)
		payload = self.get_encrypted_payload(method="payment_status")

		response = requests.post(url, headers=headers, data=payload, timeout=BANK_HTTP_TIMEOUT)

		log_id = create_api_log(
			response,
			action="Payment Status",
			account_config=self.get_account_config("payment_status"),
			ref_doctype=payment_details.parenttype or payment_details.doctype,
			ref_docname=payment_details.parent or payment_details.name,
			unique_id=unique_id,
			connector=self,
		)

		return self.get_decrypted_response(
			response, method="payment_status", log_id=log_id
		)

	def generate_otp(self):
		self.update_client_details("generate_otp")
		payment_details = self.payment_doc if not self.bulk_transaction else self.doc

		url = self.urls.generate_otp
		headers = self.headers(payment_details.mode_of_transfer)
		payload = self.get_encrypted_payload(method="generate_otp")

		response = requests.post(url, headers=headers, data=payload)

		log_id = create_api_log(
			response,
			action="Generate OTP",
			account_config=self.get_account_config("generate_otp"),
			ref_doctype=payment_details.parenttype or payment_details.doctype,
			ref_docname=payment_details.parent or payment_details.name,
			connector=self,
		)

		return self.get_decrypted_response(
			response, method="generate_otp", log_id=log_id
		)

	def get_priority(self, mode_of_transfer):
		return {"RTGS": "0001", "IMPS": "0100"}.get(mode_of_transfer, "0010")

	def get_encrypted_payload(self, method):
		connector_doc = self

		payment_details = self.payment_doc if not self.bulk_transaction else self.doc

		data = self.get_account_config(method)

		if self.bulk_transaction and (method not in ["bank_balance", "bank_statement"]):
			encrypted_key = self.rsa_encrypt_key(
				self.AES_KEY, self.get_file_relative_path(connector_doc.public_key)
			)

			return json.dumps(
				{
					"requestId": get_id(10, payment_details.name),
					"service": "",
					"oaepHashingAlgorithm": "NONE",
					"encryptedKey": encrypted_key,
					"encryptedData": self.aes_encrypt_data(data, self.AES_KEY),
					"clientInfo": "",
					"optionalParam": "",
					"iv": b64encode(self.IV).decode("utf-8"),
				}
			)
		else:
			public_key_path = self.get_file_relative_path(connector_doc.public_key)
			return self.rsa_encrypt_data(data, public_key_path)

	def get_account_config(self, method):
		payment_details = self.payment_doc if not self.bulk_transaction else self.doc

		if "A2A" in payment_details.get("mode_of_transfer", ""):
			payment_details.mode_of_transfer = "Intra Bank Transfer"

		data = {}
		method_map = {
			"register": self.set_register_data,
			"registration_status": self.set_registration_status_data,
			"generate_otp": self.set_otp_data,
			"make_payment": self.set_payment_data,
			"payment_status": self.set_payment_status_data,
			"bank_balance": self.set_balance_data,
			"bank_statement": self.set_statement_data,
		}

		if method in method_map:
			method_map[method](data)

		return data

	def set_register_data(self, data):
		connector_doc = self
		data.update(
			{
				"AGGRNAME": connector_doc.aggr_name,
				"AGGRID": connector_doc.aggr_id,
				"CORPID": connector_doc.corp_id,
				"USERID": connector_doc.corp_usr,
				"URN": connector_doc.urn,
				"ALIASID": "",
			}
		)

	def set_registration_status_data(self, data):
		connector_doc = self
		data.update(
			{
				"AGGRNAME": connector_doc.aggr_name,
				"AGGRID": connector_doc.aggr_id,
				"CORPID": connector_doc.corp_id,
				"USERID": connector_doc.corp_usr,
				"URN": connector_doc.urn,
			}
		)

	def set_statement_data(self, data):
		connector_doc = self
		payload_details = self.doc

		from_date = getdate(payload_details.get("from_date", "")).strftime("%d-%m-%Y")
		to_date = getdate(payload_details.get("to_date", "")).strftime("%d-%m-%Y")

		data.update(
			{
				"AGGRID": connector_doc.aggr_id,
				"CORPID": connector_doc.corp_id,
				"USERID": connector_doc.statement_corp_usr,
				"URN": connector_doc.urn,
				"FROMDATE": from_date,
				"TODATE": to_date,
				"ACCOUNTNO": connector_doc.account_number,
			}
		)
		if payload_details.get("paginated"):
			data.update({"CONFLG": "N"})
		if payload_details.get("last_transaction_id"):
			data.update(
				{"CONFLG": "Y", "LASTTRID": payload_details.get("last_transaction_id")}
			)

	def set_balance_data(self, data):
		connector_doc = self

		data.update(
			{
				"AGGRID": connector_doc.aggr_id,
				"CORPID": connector_doc.corp_id,
				"USERID": connector_doc.balance_corp_usr,
				"URN": connector_doc.urn,
				"ACCOUNTNO": connector_doc.account_number,
			}
		)

	def set_otp_data(self, data):
		connector_doc = self
		payment_details = self.payment_doc if not self.bulk_transaction else self.doc

		unique_id = "".join(re.findall(r"[0-9a-zA-Z]", payment_details.name))[-10:]

		if self.bulk_transaction:
			data.update(
				{
					"CORPID": connector_doc.corp_id,
					"USERID": connector_doc.corp_usr,
					"AGGRID": connector_doc.aggr_id,
					"AGGRNAME": connector_doc.aggr_name,
					"URN": connector_doc.urn,
					"UNIQUEID": unique_id,
					"AMOUNT": str(payment_details.total),
				}
			)

	def get_transaction_type(self, bank, mode_of_transfer=None):
		if bank == "ICICI Bank":
			return "TPA"
		if mode_of_transfer == "RTGS":
			return "RTG"
		if mode_of_transfer == "IMPS":
			return "IFS"

		return "RGS"

	@staticmethod
	def is_icici_internal(payment_details):
		"""ICICI -> ICICI (internal) leg, decided by the BENEFICIARY IFSC FIRST: an IFSC
		starting with ICIC is ICICI Bank by definition, regardless of whether the payload
		carries the bank name — callers often send the IFSC without the bank, and keying
		the internal path on the bank name alone routed those as external transfers, which
		ICICI rejects (103354 "Invalid Bank/Branch Identifier"). The bank name remains a
		fallback signal for a payload that names the bank but lacks the IFSC."""
		ifsc = (payment_details.get("branch_code") or "").strip().upper()
		if ifsc.startswith("ICIC"):
			return True
		return (payment_details.get("bank") or "").strip() == "ICICI Bank"

	def set_payment_data(self, data):
		connector_doc = self
		payment_details = self.payment_doc if not self.bulk_transaction else self.doc
		file_reference_id = "".join(re.findall(r"[0-9a-zA-Z]", payment_details.name))[
			-10:
		]

		unique_id = "".join(re.findall(r"[0-9a-zA-Z]", payment_details.name))[-10:]

		if self.bulk_transaction:
			data.update(
				{
					"FILE_DESCRIPTION": file_reference_id,
					"CORP_ID": connector_doc.corp_id,
					"USER_ID": connector_doc.corp_usr,
					"AGGR_ID": connector_doc.aggr_id,
					"AGGR_NAME": connector_doc.aggr_name,
					"URN": connector_doc.urn,
					"UNIQUE_ID": unique_id,
					"AGOTP": str(payment_details.otp),
					"FILE_NAME": f"{file_reference_id}.txt",
					"FILE_CONTENT": self.construct_payment_details_content(
						payment_details, connector_doc
					),
				}
			)
			return
		else:
			workflow_reqd = "Y"
			if payment_details.mode_of_transfer.lower() not in ["neft", "imps"]:
				workflow_reqd = "N"
			if not self.testing:
				workflow_reqd = "Y"

			# ICICI -> ICICI (internal) MUST use the generic ICICI IFSC "ICIC0000011" with
			# TXNTYPE=TPA — exactly what the old production ICICI integration
			# (bank_api_integration: IFSC="ICIC0000011", TXNTYPE="Internal Payments") sent for
			# internal transfers; ICICI rejects an internal leg routed externally with 103354
			# "Invalid Bank/Branch Identifier". The internal decision is IFSC-first (see
			# is_icici_internal): a payload may carry the ICIC IFSC without the bank name.
			# External beneficiaries keep their own IFSC (branch_code). Account numbers /
			# IFSC are codes: sent as stripped strings (a stray tab in the IFSC has already
			# rejected a live payment), never numerically cast.
			internal = self.is_icici_internal(payment_details)
			data.update(
				{
					"AGGRID": connector_doc.aggr_id,
					"AGGRNAME": connector_doc.aggr_name,
					"CORPID": connector_doc.corp_id,
					"USERID": connector_doc.corp_usr,
					"URN": connector_doc.urn,
					"UNIQUEID": payment_details.name,
					"DEBITACC": cstr(connector_doc.account_number).strip(),
					"CREDITACC": cstr(payment_details.bank_account_no).strip(),
					"IFSC": "ICIC0000011"
					if internal
					else cstr(payment_details.branch_code).strip(),
					"AMOUNT": cstr(payment_details.amount),
					"CURRENCY": "INR",
					"TXNTYPE": self.get_transaction_type(
						"ICICI Bank" if internal else payment_details.bank,
						mode_of_transfer=payment_details.mode_of_transfer,
					),
					"PAYEENAME": self.clean_string(payment_details.account_name),
					"REMARKS": f"{payment_details.party_type} {self.clean_string(payment_details.party)}",
					"WORKFLOW_REQD": workflow_reqd,
					"BENLEI": payment_details.lei or "",
				}
			)

	def set_payment_status_data(self, data):
		connector_doc = self
		payment_details = self.payment_doc if not self.bulk_transaction else self.doc
		unique_id = "".join(re.findall(r"[0-9a-zA-Z]", payment_details.name))[-10:]

		if self.bulk_transaction:
			payment_doc = self.doc
			data.update(
				{
					"CORPID": connector_doc.corp_id,
					"USERID": connector_doc.status_corp_usr,
					"AGGRID": connector_doc.aggr_id,
					"URN": connector_doc.urn,
					"UNIQUEID": unique_id,
					"FILESEQNUM": payment_doc.file_sequence_number,
					"ISENCRYPTED": "N",
				}
			)
			return

		data.update(
			{
				"AGGRID": connector_doc.aggr_id,
				"CORPID": connector_doc.corp_id,
				"USERID": connector_doc.corp_usr,
				"URN": connector_doc.urn,
				"UNIQUEID": payment_details.name,
			}
		)

	def get_decrypted_response(self, response, method, log_id=None):
		connector_doc = self
		res_dict = frappe._dict({})
		if response.ok:
			response = response.text

			if self.bulk_transaction and method not in [
				"bank_balance",
				"bank_statement",
			]:
				response = json.loads(response)
				decrypted_key = self.rsa_decrypt_key(
					response.get("encryptedKey"),
					self.get_file_relative_path(connector_doc.private_key),
				)
				decrypted_data = self.aes_decrypt_data(
					response.get("encryptedData"), decrypted_key
				)

			elif method == "bank_statement":
				response = json.loads(response)
				decrypted_key = self.rsa_decrypt_key(
					response.get("encryptedKey"),
					self.get_file_relative_path(connector_doc.private_key),
				)
				decrypted_data = self.rsa_with_aes_decrypt_data(
					response.get("encryptedData"), decrypted_key
				)
			else:
				decrypted_data = self.rsa_decrypt_data(
					response, self.get_file_relative_path(connector_doc.private_key)
				)

			self.set_decrypted_response(log_id, decrypted_data)

			self.get_formated_response(decrypted_data, res_dict, method)
		else:
			res_dict.status = "Request Failure"
			res_dict.message = response.text or response.status_code

		return res_dict

	def get_formated_response(self, data, res_dict, method):
		if isinstance(data, str):
			data = json.loads(data)

		data = frappe._dict(data)

		if self.bulk_transaction or method in ["bank_balance", "bank_statement"]:
			self.handle_bulk_transaction_response(data, res_dict, method)
			return res_dict

		if method == "register":
			if data.get("RESPONSE") == "SUCCESS":
				res_dict.status = "success"
				res_dict.message = data.get("MESSAGE", "")
			else:
				res_dict.status = "Failed"
				res_dict.message = data.get("errormessage") or data.get("Message")

		elif method == "registration_status":
			if data.get("RESPONSE") == "Success":
				res_dict.status = "success"
				res_dict.message = data.get(
					"MESSAGE", "Registration Completed Successfully"
				)
			else:
				res_dict.status = "Failed"
				res_dict.message = data.get("errormessage") or data.get("Message")

		elif method == "make_payment" and data:
			if data.STATUS in [
				"SUCCESS",
				"PENDING",
				"PENDING FOR PROCESSING",
				"PENDING FOR APPROVAL",
			]:
				res_dict.payment_status = "ACCEPTED"
				res_dict.message = f"Payment {data.get('STATUS', '').title()}"
				res_dict.summary_details = {
					self.payment_doc.name: {"payment_status": "Accepted"}
				}
			elif data.UTRNUMBER:
				res_dict.status = "ACCEPTED"
				res_dict.message = data.UTRNUMBER
				res_dict.summary_details = {
					self.payment_doc.name: {"payment_status": "Accepted"}
				}
			elif data.STATUS == "DUPLICATE":
				res_dict.payment_status = "ACCEPTED"
				res_dict.message = f"Payment {data.get('STATUS', '').title()}"
				res_dict.summary_details = {
					self.payment_doc.name: {"payment_status": "Failed"}
				}
			elif data.errorCode == "997":
				res_dict.payment_status = "Request Failure"
				res_dict.message = f"{data.errorCode} : {data.description}"
			else:
				res_dict.payment_status = "FAILED"
				res_dict.message = f"Invalid Status : {data.STATUS}"

		elif method == "payment_status" and data:
			if data.STATUS == "SUCCESS":
				res_dict.payment_status = "PROCESSED"
				res_dict.summary_details = {
					self.payment_doc.name: {
						"status": "Processed",
						"utr_number": data.UTRNUMBER,
						"message": data.MESSAGE or "Payment Completed",
					}
				}
			elif data.STATUS in [
				"PENDING",
				"PENDING FOR PROCESSING",
				"PROCESSING",
				"PENDING FOR APPROVAL",
			]:
				res_dict.payment_status = "PROCESSED"
				res_dict.summary_details = {
					self.payment_doc.name: {
						"status": "Pending",
						"message": data.MESSAGE or "Payment Pending",
					}
				}
			elif data.STATUS == "FAILURE":
				res_dict.payment_status = "PROCESSED"
				res_dict.summary_details = {
					self.payment_doc.name: {
						"status": "Failed",
						"message": data.MESSAGE or "Payment Failed",
					}
				}
			else:
				res_dict.payment_status = "PROCESSED"
				res_dict.summary_details = {
					self.payment_doc.name: {
						"status": "Request Failure",
						"message": data.MESSAGE or "Payment Request Failure",
					}
				}

	def handle_bulk_transaction_response(self, data, res_dict, method):
		if method == "generate_otp" and data:
			if data.get("RESPONSE") == "Success":
				res_dict.status = "success"
				res_dict.message = data.get("MESSAGE")

			elif data.get("errormessage"):
				res_dict.status = "Failed"
				err_msg = None

				if data.get("ErrorCode"):
					err_msg = self.get_error_description(data.get("ErrorCode"))

				res_dict.message = (
					err_msg or data.get("errormessage") or data.get("Message")
				)

		elif method == "make_payment" and data:
			if data.get("FILE_SEQUENCE_NUM"):
				res_dict.payment_status = "ACCEPTED"
				res_dict.message = data.get("MESSAGE_DESC")
				res_dict.file_sequence_number = data.get("FILE_SEQUENCE_NUM")

				res_dict.summary_details = self.get_summary_details("Accepted")

			elif data.get("errormessage") or data.get("ErrorCode"):
				res_dict.payment_status = "ACCEPTED"
				err_msg = ""

				if data.get("ErrorCode"):
					err_msg = self.get_error_description(data.get("ErrorCode"))
				res_dict.message = (
					err_msg or data.get("errormessage") or data.get("Message")
				)

				res_dict.summary_details = self.get_summary_details("Failed")

		elif method == "payment_status" and data:
			if file_status := data.get("XML", {}).get("FILE_STATUS"):
				res_dict.payment_status = "PROCESSED"
				if file_status in ["REJ", "REC"]:
					res_dict.message = "Payment Rejected"
				elif file_status in ["FAL"]:
					res_dict.message = "Payment Failed"

				res_dict.summary_details = {}

				if (
					data.get("XML")
					.get("FILEUPLOAD_BINARY_OUTPUT")
					.get("Records")
					.get("Record")
				):
					res_dict.summary_details = self.format_payment_status(
						data.get("XML", {})
						.get("FILEUPLOAD_BINARY_OUTPUT", {})
						.get("Records", {})
						.get("Record", "")
					)

			elif data.get("errormessage") or data.get("ErrorCode"):
				res_dict.status = "Failed"
				err_msg = None
				if data.get("ErrorCode"):
					err_msg = self.get_error_description(data.get("ErrorCode"))

				res_dict.message = (
					err_msg or data.get("errormessage") or data.get("Message")
				)

		elif method == "bank_balance" and data:
			if data.get("RESPONSE") == "SUCCESS":
				res_dict.server_status = "Success"
				res_dict.balance = data.get("EFFECTIVEBAL", 0)
				res_dict.date = data.get("DATE", "")
			else:
				res_dict.server_status = "Failed"
				res_dict.message = data

		elif method == "bank_statement" and data:
			records = data.get("Record", [])
			transactions = []

			if data.get("RESPONSE") == "SUCCESS":
				if isinstance(records, dict):
					records = [records]
				for txn in records:
					transaction = {
						"transaction_date": txn.get("TXNDATE", ""),
						"transaction_amount": txn.get("AMOUNT"),
						"reference_number": txn.get("TRANSACTIONID")
						or txn.get("CHEQUENO"),
						"transaction_description": txn.get("REMARKS", ""),
					}
					transactions.append(transaction)

			res_dict.server_status = "Success"
			res_dict.bank_statements = transactions
			res_dict.last_transaction_id = data.get("LISTTRID")

		return res_dict

	def set_decrypted_response(self, log_id, response_data):
		if isinstance(response_data, str):
			response_data = json.loads(response_data)

		response_data = json.dumps(response_data, indent=4)

		super().set_decrypted_response(log_id, response_data)

	def get_cert(self):
		return (
			self.get_file_relative_path(self.cert_file),
			self.get_file_relative_path(self.private_key),
		)

	def update_client_details(self, method=None):
		if not method:
			frappe.throw("Invalid Method")

		if method == "bank_balance":
			self.client_key = self.get_password("balance_client_key")
		elif method == "bank_statement":
			self.client_key = self.get_password("statement_client_key")
		else:
			self.client_key = self.get_password("client_key")

	def get_bank_balance(self):
		if not self.balance_check:
			frappe.throw(_("Bank Balance Check is not enabled."))

		self.update_client_details("bank_balance")
		url = self.urls.bank_balance
		headers = self.headers(params={"content-type": "text/plain"})
		payload = self.get_encrypted_payload(method="bank_balance")

		response = requests.post(url, headers=headers, data=payload)

		log_id = create_api_log(
			response,
			action="Bank Balance",
			account_config=self.get_account_config("bank_balance"),
			ref_doctype="Bank Balance",
			ref_docname=self.account_number,
			connector=self,
		)

		return self.get_decrypted_response(
			response, method="bank_balance", log_id=log_id
		)

	def get_bank_statement(self):
		if not self.statement_fetch:
			frappe.throw(_("Bank Statement Check is not enabled."))

		self.update_client_details("bank_statement")
		url = self.urls.bank_statement
		headers = self.headers(params={"content-type": "text/plain"})
		payload = self.get_encrypted_payload(method="bank_statement")

		response = requests.post(url, headers=headers, data=payload)

		log_id = create_api_log(
			response,
			action="Bank Statement",
			account_config=self.get_account_config("bank_statement"),
			ref_doctype="Bank Statement",
			ref_docname=self.account_number,
			connector=self,
		)

		return self.get_decrypted_response(
			response, method="bank_statement", log_id=log_id
		)

	def get_error_description(self, code):
		return {
			"108363": "The entered date cannot be prior to the current date.",
			"108590": "The header amount does not equal the sum of records in the uploaded file.",
			"101043": "Type system exception occurred",
			"999481": "Dear Customer, This facility is available for select customer segments only. For any further queries please write to corporatecare@icicibank.com",
			"108588": "The total number of records is not same in header and file records.",
			"104668": "Please select the proper files and attach again.",
			"110370": "Please select the proper files and attach again.",
			"104344": "The cut-off time for this transaction has already passed. This action cannot be performed with the current transaction date.",
			"999936": "Transactions already processed with same unique ID, please use exclusive unique id for each transaction.",
			"111267": "The record ID is not present in the file.",
			"110004": "Enter the valid date as the selected date is a bank holiday.",
			"994006": "OTP Validation Failed",
			"107889": "OTP Validation Failed",
			"100901": "Consumption limits not defined for the user. Transaction cannot be processed. Please contact the bank administrator",
			"104666": "File with the same name is already uploaded",
		}.get(str(code), "Unknown Error")

	def construct_payment_details_content(self, payment_doc, connector_doc):
		file_reference_id = "".join(re.findall(r"[0-9a-zA-Z]", payment_doc.name))[-10:]

		content = []
		first_line = "{}|{}|{}|{}|{}|{}|{}|{}^".format(
			"FHR",
			len(payment_doc.summary) + 1,
			getdate(nowdate()).strftime("%m/%d/%Y"),
			file_reference_id,
			flt(payment_doc.total),
			"INR",
			connector_doc.account_number,
			"0011",
		)
		content.append(first_line)
		second_line = "{}|{}|{}|{}|{}|{}|{}|{}|{}^".format(
			"MDR",
			connector_doc.account_number,
			"0011",
			payment_doc.company.replace(" ", "")[:30],
			flt(payment_doc.total),
			"INR",
			file_reference_id,
			"ICIC0000011",
			"WIB",
		)
		content.append(second_line)
		for payment_row in payment_doc.summary:
			if isinstance(payment_row, str):
				payment_row = json.loads(payment_row)
			payment_row = frappe._dict(payment_row)
			if payment_doc.company_bank == payment_row.bank:
				mcw_st = "{}|{}|{}|{}|{}|{}|{}|{}|{}^".format(
					"MCW",
					payment_row.bank_account_no,
					payment_row.bank_account_no[:4],
					payment_row.account_name.replace(" ", "")[:30],
					flt(payment_row.amount),
					"INR",
					payment_row.name,
					payment_row.branch_code,
					"WIB",
				)
				content.append(mcw_st)
			else:
				mco_st = "{}|{}|{}|{}|{}|{}|{}|{}|{}^".format(
					"MCO",
					payment_row.bank_account_no,
					"0011",
					payment_row.account_name.replace(" ", "")[:30],
					flt(payment_row.amount),
					"INR",
					payment_row.name,
					"NFT",
					payment_row.branch_code,
				)
				content.append(mco_st)
		result = "\n".join(content)
		byte_like = str.encode(result)
		encode_result = b64encode(byte_like).decode("utf-8")
		return encode_result

	def format_payment_status(self, records):
		if isinstance(records, str):
			records = json.loads(records)

		keys = [
			"transaction_type",
			"network_id",
			"credit_account_number",
			"debit_account_number",
			"ifsc_code",
			"currency",
			"total_amount",
			"host_reference_number",
			"host_response_code",
			"host_response_message",
			"transaction_remarks",
			"transaction_status",
		]

		result = {}
		for row in records[1:]:
			values = row.split("|")
			row_dict = dict(zip(keys, values))
			if row_dict.get("transaction_status", "") == "SUC":
				result.update(
					{
						row_dict.get("transaction_remarks"): {
							"status": "Processed",
							"utr_number": row_dict.get("host_reference_number", ""),
							"message": row_dict.get(
								"host_response_message", "Payment Accepted"
							),
						}
					}
				)
			if row_dict.get("transaction_status", "") == "FAL":
				result.update(
					{
						row_dict.get("transaction_remarks"): {
							"status": "Failed",
							"message": row_dict.get(
								"host_response_message", "Payment Failed"
							),
						}
					}
				)
			if row_dict.get("transaction_status", "") in ["REJ", "REC"]:
				result.update(
					{
						row_dict.get("transaction_remarks"): {
							"status": "Rejected",
							"message": row_dict.get(
								"host_response_message", "Payment Rejected"
							),
						}
					}
				)

		return result

	def get_file_status(self, key):
		return {
			"GIP": "This is the intermediate state where GFP batches gets executed",
			"PFI": "(Pending for insertion)This is the state where bulk has been upload and transaction is completed from front end aand awaiting for the batch process to be completed.",
			"ENT": "Entered state for the transaction once bulk transaction is initiated",
			"MIR": "Manual intervention required: - goes for reversal",
			"STS": "Success",
			"FAL": "Failure",
			"PPD": "Partially processed",
			"REJ": "Transaction has gone to rejected case",
			"ATH": "status after process scheduler batch run is completed. Its before GFP batch.",
			"CRP": "Credit reversal pending",
			"REC": "when initiator itself canceled or recalled the txn",
		}.get(key, "Unknown issue occured")
