# Copyright (c) 2024, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

import base64
import json
import random
import re
import string
import time

import frappe
import requests
from Crypto.Cipher import AES, PKCS1_v1_5 as Cipher_PKCS1_v1_5
from Crypto.PublicKey import RSA
import gzip
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from frappe import _
from frappe.utils import flt, getdate

from urllib.parse import urlparse

import india_banking_connector.utils as utils
from india_banking_connector.connectors.bank_connector import BankConnector
from india_banking_connector.india_banking_connector.doctype.bank_request_log.bank_request_log import (
	create_api_log,
)


class HDFCConnector(BankConnector):
	bank = "HDFC Bank"

	__all__ = [
		"initiate_payment",
		"get_payment_status",
		"get_bank_balance",
		"get_balance",
		"get_bank_statement",
	]

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		self.bulk_transaction = kwargs.get("bulk_transaction", 0)
		self.doc = frappe._dict(kwargs.get("doc", {}))
		self.payment_doc = frappe._dict(kwargs.get("payment_doc", {}))

	@property
	def urls(self):
		if self.bulk_transaction:
			frappe.throw("Bulk transactions are not supported")

		return super().urls

	@property
	def headers(self):
		return {
			"apikey": self.get_password("client_key"),
			"scope": self.scope,
			"transactionId": utils.get_id(),
			"Content-Type": "application/jose",
			"Authorization": "Bearer " + self.get_oauth_token(),
		}

	def initiate_payment(self):
		payment_details = self.payment_doc if not self.bulk_transaction else self.doc
		unique_id = (
			self.payment_doc.name if not self.bulk_transaction else self.doc.name
		)

		if existing_payment_response := self.validate_duplicate_payments(
			unique_id=unique_id
		):
			return existing_payment_response

		url = self.urls.make_payment
		headers = self.headers
		payload = self.get_encrypted_payload(method="make_payment")

		response = requests.post(
			url,
			headers=headers,
			data=payload,
			cert=self.get_cert(),
			proxies=self.get_proxies(),
			timeout=30,
		)

		log_id = create_api_log(
			response,
			action="Initiate Payment",
			account_config=self.get_account_config("make_payment"),
			ref_doctype=payment_details.parenttype or payment_details.doctype,
			ref_docname=payment_details.parent or payment_details.name,
			unique_id=unique_id,
			connector=self,
		)

		return self.get_decrypted_response(
			response, method="make_payment", log_id=log_id
		)

	def get_payment_status(self):
		payment_details = self.payment_doc if not self.bulk_transaction else self.doc
		unique_id = (
			self.payment_doc.name if not self.bulk_transaction else self.doc.name
		)

		url = self.urls.payment_status
		headers = self.headers
		payload = self.get_encrypted_payload(method="payment_status")

		response = requests.post(
			url,
			headers=headers,
			data=payload,
			cert=self.get_cert(),
			proxies=self.get_proxies(),
			timeout=30,
		)

		log_id = create_api_log(
			response,
			action="Payment Status",
			account_config=self.get_account_config("payment_status"),
			ref_doctype=payment_details.parenttype or payment_details.doctype,
			ref_docname=payment_details.parent or payment_details.name,
			unique_id=unique_id,
			connector=self,
		)
		try:
			return self.get_decrypted_response(
				response, method="payment_status", log_id=log_id
			)
		except Exception as e:
			frappe.log_error(
				"Decryption Failed", frappe.get_traceback(with_context=True)
			)
			return {
				"status": "Request Failure",
				"message": str(e),
				"response": response,
			}

	def set_decrypted_response(self, log_id, response_data):
		if isinstance(response_data, str):
			response_data = json.loads(response_data)

		response_data = json.dumps(response_data, indent=4)

		super().set_decrypted_response(log_id, response_data)

	def get_decrypted_response(self, response, method, log_id=None):
		res_dict = frappe._dict({})
		if response.ok:
			if method in ["bank_balance", "bank_statement"]:
				try:
					resp_json = response.json()
					decrypted_data = self.decrypt_medium_with_ds(resp_json)
					if log_id:
						self.set_decrypted_response(log_id, decrypted_data)
					self.get_formated_response(decrypted_data, res_dict, method)
				except Exception as e:
					frappe.log_error(
						f"HDFC {method} Decryption Error", frappe.get_traceback()
					)
					res_dict.server_status = "Failed"
					res_dict.error = str(e)
			else:
				jwe_decrypted = self.jwe_decrypt(
					response.text, self.get_file_content(self.private_key)
				)
				jws_verified = self.jws_verify(
					jwe_decrypted, self.get_file_content(self.public_key)
				)

				self.set_decrypted_response(log_id, jws_verified)
				self.get_formated_response(jws_verified, res_dict, method)
		else:
			res_dict.status = "Request Failure"
			res_dict.server_status = "Failed"
			res_dict.error = response.text
			if self.get("mark_expired_status_as_failed"):
				self.check_expired_payment(response, method, res_dict)

		return res_dict

	def check_expired_payment(self, response, method, res_dict):
		try:
			if method == "payment_status":
				error_response = json.loads(response.text)
				if errors := error_response.get("errors"):
					error_code = errors[0].get("code")
					if error_code == "611081":
						msg, sts = self.get_status_description(error_code)
						res_dict.payment_status = "PROCESSED"
						res_dict.summary_details = {
							self.payment_doc.name: {
								"status": sts,
								"message": msg,
							}
						}
		except Exception:
			# ignoring the exception
			pass

	def get_formated_response(self, data, res_dict, method):
		if isinstance(data, str):
			data = json.loads(data)

		data = frappe._dict(data)

		if method == "make_payment":
			status_text = (
				frappe.utils.cstr(data.get("Transaction") or data.get("STATUS") or "")
				.strip()
				.upper()
			)
			if status_text in ["ACCEPTED", "SUCCESS"]:
				res_dict.payment_status = "ACCEPTED"
				res_dict.message = data.get("Transaction") or data.get("MESSAGE") or "Payment Accepted"
				res_dict.summary_details = {
					self.payment_doc.name: {
						"payment_status": "Accepted",
						"message": res_dict.message,
					}
				}
			else:
				res_dict.payment_status = "FAILED"
				res_dict.message = data.get("ERROR_MESSAGE") or data.get("MESSAGE") or data.get("Transaction") or "Payment Failed"
				res_dict.summary_details = {
					self.payment_doc.name: {
						"payment_status": "Failed",
						"message": res_dict.message,
					}
				}

		elif method == "payment_status":
			msg, utr, sts = self.get_msg_utr_number(data)

			res_dict.payment_status = "PROCESSED" if sts != "" else "FAILED"
			res_dict.summary_details = {
				self.payment_doc.name: {
					"status": sts,
					"utr_number": utr,
					"message": msg,
				}
			}

		elif method == "bank_balance" and data:
			resp_str = (
				data.get("responseString", {})
				if isinstance(data, dict)
				else {}
			)
			avail_bal = resp_str.get("availableBalance")
			if avail_bal is not None:
				res_dict.server_status = "Success"
				res_dict.status = "SUCCESS"
				res_dict.balance = frappe.utils.flt(avail_bal)
				res_dict.available_balance = frappe.utils.flt(avail_bal)
				res_dict.clear_balance = frappe.utils.flt(resp_str.get("clearBalance", 0))
				res_dict.net_available_balance = frappe.utils.flt(resp_str.get("netAvailableBalance", 0))
				res_dict.hold_amount = frappe.utils.flt(resp_str.get("holdAmount", 0))
				res_dict.od_limit = frappe.utils.flt(resp_str.get("odlimit", 0))
				res_dict.unclear_balance = frappe.utils.flt(resp_str.get("unClearBalance", 0))
				res_dict.account_status = resp_str.get("accountStatus")
				res_dict.decrypted_data = data
				res_dict.date = getdate()
			else:
				txn_status = resp_str.get("transactionStatus", {})
				res_dict.server_status = "Failed"
				res_dict.status = "FAILED"
				res_dict.message = txn_status.get("replyText") or str(data)
				res_dict.bank_message = txn_status.get("replyText") or str(data)
				res_dict.error_code = txn_status.get("errorCode")
				res_dict.decrypted_data = data

		elif method == "bank_statement" and data:
			transactions = []
			stmt_data = data.get("responseString", {}) if isinstance(data, dict) else {}
			raw_txns = (
				stmt_data.get("transactionList")
				or stmt_data.get("Record")
				or stmt_data.get("transactions")
				or []
			)
			if isinstance(raw_txns, dict):
				raw_txns = [raw_txns]

			for txn in raw_txns:
				amt = frappe.utils.flt(txn.get("amount") or txn.get("txnAmount", 0))
				dr_cr = str(txn.get("drCrFlag") or txn.get("txnType") or txn.get("type") or "").upper()
				if dr_cr in ["D", "DR", "DEBIT"]:
					amt = -1 * abs(amt)
				else:
					amt = abs(amt)

				transactions.append({
					"transaction_date": txn.get("txnDate") or txn.get("valueDate") or txn.get("transactionDate") or "",
					"transaction_amount": amt,
					"reference_number": txn.get("txnRefNo") or txn.get("referenceNo") or txn.get("reference_number") or "",
					"transaction_description": txn.get("narration") or txn.get("txnDesc") or txn.get("description") or "",
				})

			res_dict.server_status = "Success"
			res_dict.status = "SUCCESS"
			res_dict.bank_statements = transactions
			res_dict.decrypted_data = data

	def get_msg_utr_number(self, data):
		if "ALL_RECORDS" in data and data["ALL_RECORDS"]:
			record = data["ALL_RECORDS"][0] or {}

			if record:
				if "TXN_STATUS" in record and record["TXN_STATUS"]:
					utr = record.get("UTR_NO", None) or record.get("TXN_REFERENCE_NO")
					if (
						not utr
						and record["TXN_STATUS"] == "Processed"
						and record["TRANSFER_TYPE"] == "Intra Bank Transfer"
					):
						utr = record.get(
							"PAYMENTREFNO"
						)

					msg, sts = self.get_status_description(record.get("OD_STATUS"))
					return msg, utr, sts
			else:
				raise Exception(f"Error in processing payment status: {data}")
			return

	def get_encrypted_payload(self, method):
		if method in ["bank_balance", "bank_statement"]:
			prefix = "BAL" if method == "bank_balance" else "STMT"
			txn_id = getattr(self, "_current_txn_id", None) or f"{prefix}{utils.get_id()}"
			self._current_txn_id = txn_id
			config = self.get_account_config(method)
			return self.encrypt_medium_with_ds(config, txn_id)

		headers = {"typ": "JWS", "kid": self.generate_kid(self.sign_key)}
		jws_signed = self.sign_jws(
			self.get_account_config(method),
			self.get_file_content(self.private_key),
			headers,
		)

		return self.jwe_encrypt(
			jws_signed,
			self.get_file_content(self.public_key),
			kid=self.generate_kid(self.public_key),
		)

	def get_account_config(self, method):
		conector_doc = self

		if method == "bank_balance":
			txn_id = getattr(self, "_current_txn_id", None) or f"BAL{utils.get_id()}"
			self._current_txn_id = txn_id
			partner_id = getattr(self, "partner_id", None)
			if not partner_id and self.payment_doc and self.payment_doc.get("partner_id"):
				partner_id = self.payment_doc.get("partner_id")

			return {
				"sessionContext": {
					"bankCode": getattr(self, "bank_code", None) or "08",
					"channel": getattr(self, "channel", None) or "APIGW",
					"userId": getattr(self, "user_id", None) or "DevUser01",
					"transactionBranch": getattr(self, "transaction_branch", None) or "089999",
					"externalReferenceNo": txn_id,
					"transactingPartyCode": self.scope,
					"userReferenceNumber": txn_id,
				},
				"CASABasicBalanceInquiryRequestDTO": {
					"accountNo": self.clean_string(self.account_number),
					"partnerId": str(partner_id or "").strip(),
				},
			}
		elif method == "bank_statement":
			txn_id = getattr(self, "_current_txn_id", None) or f"STMT{utils.get_id()}"
			self._current_txn_id = txn_id
			statement_details = self.doc or self.payment_doc or {}
			partner_id = str(getattr(self, "partner_id", None) or "ZERODHA3").strip()

			return {
				"ReportGenerationDTO": {
					"module": "CASA",
					"reportId": "XFAPI0066",
					"reportParams": [
						{"paramName": "AccountNumber", "paramValue": self.clean_string(self.account_number)},
						{"paramName": "StatementFromTime", "paramValue": "00:00:00"},
						{"paramName": "StatementToTime", "paramValue": "23:59:59"},
						{"paramName": "CumulativeFlag", "paramValue": "N"},
						{"paramName": "SourceId", "paramValue": partner_id},
						{"paramName": "FlagValidateSourceId", "paramValue": "N"},
						{"paramName": "FlagValidateMandate", "paramValue": "N"},
					],
					"userId": getattr(self, "user_id", None) or "189000226",
				},
				"sessionContext": {
					"channel": getattr(self, "channel", None) or "APIGW",
					"bankCode": getattr(self, "bank_code", None) or "08",
					"userId": getattr(self, "user_id", None) or "DevUser01",
					"externalReferenceNo": txn_id,
					"transactionBranch": getattr(self, "transaction_branch", None) or "089999",
					"transactingPartyCode": getattr(self, "partner_id", None) or self.scope,
				},
			}

		payment_details = self.payment_doc if not self.bulk_transaction else self.doc
		raw_mode = (
			getattr(payment_details, "mode_of_transfer", "")
			or getattr(payment_details, "FILTER1_VALUE_TXT", "")
			or ""
		).upper()

		if any(k in raw_mode for k in ["A2A", "INTRA", "BOOK", "INTERNAL", "ACCOUNT TO ACCOUNT"]):
			mode_of_transfer = "Intra Bank Transfer"
		elif "RTGS" in raw_mode:
			mode_of_transfer = "RTGS"
		elif "IMPS" in raw_mode:
			mode_of_transfer = "IMPS"
		else:
			mode_of_transfer = "NEFT"

		ifsc_code = (
			getattr(payment_details, "branch_code", None)
			or getattr(payment_details, "ifsc_code", None)
			or getattr(payment_details, "custom_ifs_code", None)
			or getattr(payment_details, "branch", "")
			or ""
		)

		bene_name = re.sub(
			r"[^a-zA-Z\s]",
			"",
			getattr(payment_details, "party_name", None)
			or getattr(payment_details, "party", "")
			or "",
		).strip()[:50]

		if method == "make_payment":
			return {
				"LOGIN_ID": conector_doc.login_id,
				"INPUT_GCIF": conector_doc.scope,
				"TRANSFER_TYPE_DESC": mode_of_transfer,
				"BENE_BANK": self.clean_string(getattr(payment_details, "bank", "")),
				"INPUT_DEBIT_AMOUNT": str(getattr(payment_details, "amount", 0)),
				"INPUT_VALUE_DATE": getdate(
					getattr(payment_details, "payment_date", None) or getdate()
				).strftime("%d/%m/%Y"),
				"TRANSACTION_TYPE": "SINGLE",
				"INPUT_DEBIT_ORG_ACC_NO": self.clean_string(
					conector_doc.account_number
				),
				"INPUT_BUSINESS_PROD": conector_doc.business_prod,
				"BENE_ID": "",
				"BENE_ACC_NAME": bene_name,
				"BENE_ACC_NO": self.clean_string(
					getattr(payment_details, "bank_account_no", "")
				),
				"BENE_TYPE": "ADHOC",
				"BENE_BRANCH": ifsc_code,
				"BENE_IDN_CODE": ifsc_code,
				"EMAIL_ADDR_VIEW": getattr(payment_details, "email", ""),
				"PAYMENT_REF_NO": getattr(payment_details, "name", ""),
			}
		elif method == "payment_status":
			return {
				"LOGIN_ID": conector_doc.login_id,
				"INPUT_GCIF": conector_doc.scope,
				"TXNDATE": getdate(
					getattr(payment_details, "payment_date", None)
					or getattr(payment_details, "creation", None)
					or getdate()
				).strftime("%Y-%m-%d"),
				"FILTER1_VALUE_TXT": mode_of_transfer,
				"CBX_API_REF_NO": getattr(payment_details, "name", ""),
			}

	def get_oauth_token(self):
		params = {"grant_type": "client_credentials", "scope": self.scope}

		auth_string = (
			self.get_password("client_key") + ":" + self.get_password("client_secret")
		)
		encoded_credintial = "Basic " + base64.b64encode(auth_string.encode()).decode()

		headers = {
			"Content-Type": "application/x-www-form-urlencoded",
			"Authorization": encoded_credintial,
		}
		try:
			response = requests.post(
				self.urls.oauth_token,
				params=params,
				headers=headers,
				cert=self.get_cert(),
				proxies=self.get_proxies(),
				timeout=30,
			)

			create_api_log(response, action="Get OAuth Token", connector=self)

			if not response.ok:
				frappe.throw(
					_("Authentication failed: {0}").format(
						response.text or response.status_code
					)
				)
			token = response.json().get("access_token")
			if not token:
				frappe.throw(
					_("Authentication succeeded but no access token was returned.")
				)
			return token

		except requests.exceptions.SSLError:
			frappe.log_error("Oauth Failed", frappe.get_traceback(with_context=True))
			frappe.throw(
				_(
					"Connection failed due to a certificate mismatch. Verify the certificate and try again."
				)
			)
		except Exception:
			frappe.log_error("Oauth Failed", frappe.get_traceback(with_context=True))
			frappe.throw(
				_(
					"Connection failed. Unable to authenticate with the connector. Please verify your credentials"
				)
			)

	def get_cert(self):
		return (
			self.get_file_relative_path(self.cert_file),
			self.get_file_relative_path(self.private_key),
		)

	def get_proxies(self):
		proxies = {}
		if hasattr(self, "http_proxy") and self.http_proxy:
			proxies["http"] = self.http_proxy
		if hasattr(self, "https_proxy") and self.https_proxy:
			proxies["https"] = self.https_proxy
		if not proxies and frappe.db.exists("DocType", "HDFC Settings"):
			h_set = frappe.get_single("HDFC Settings")
			if getattr(h_set, "http_proxy", None):
				proxies["http"] = h_set.http_proxy
			if getattr(h_set, "https_proxy", None):
				proxies["https"] = h_set.https_proxy
		return proxies or None

	def encrypt_medium_with_ds(self, payload_dict, txn_id):
		"""Encrypt payload using HDFC 'Medium with DS' APIGEE specification:
		1. JWS Digital Signature using Client Private Key (SHA256withRSA, typ: JWT)
		2. AES-256-CBC encryption of (IV + JWS) using a random 32-byte key -> RequestSignatureEncryptedValue
		3. RSA encryption of 32-byte key using Bank's Public Key -> SymmetricKeyEncryptedValue
		"""
		priv_pem = self.get_file_content(self.private_key).encode("utf-8")
		priv_key_obj = serialization.load_pem_private_key(priv_pem, password=None)

		# 1. Digital Signature JWS (typ: JWT, alg: RS256)
		header = {"typ": "JWT", "alg": "RS256"}
		header_b64 = (
			base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode())
			.decode()
			.rstrip("=")
		)
		payload_b64 = (
			base64.urlsafe_b64encode(
				json.dumps(payload_dict, separators=(",", ":")).encode()
			)
			.decode()
			.rstrip("=")
		)
		signing_input = f"{header_b64}.{payload_b64}".encode()

		sig = priv_key_obj.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
		sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")
		jws_compact = f"{header_b64}.{payload_b64}.{sig_b64}"

		# 2. Symmetric key generation & AES encryption
		sym_key = "".join(
			random.choices(string.ascii_letters + string.digits, k=32)
		).encode("utf-8")
		iv = b"1234567890123456"
		iv_and_data = iv + jws_compact.encode("utf-8")
		padded_data = pad(iv_and_data, 16, style="pkcs7")
		cipher_aes = AES.new(sym_key, AES.MODE_CBC, iv)
		ciphertext = cipher_aes.encrypt(padded_data)
		req_sig_enc = base64.b64encode(ciphertext).decode("utf-8")

		# 3. Encrypt 32-byte key with Bank's Public Key (RSA/ECB/PKCS1Padding)
		pub_pem = self.get_file_content(self.public_key)
		rsa_bank_pub_key = RSA.import_key(pub_pem)
		cipher_rsa = Cipher_PKCS1_v1_5.new(rsa_bank_pub_key)
		enc_key = cipher_rsa.encrypt(sym_key)
		sym_key_enc = base64.b64encode(enc_key).decode("utf-8")

		return {
			"RequestEncryptedValue": req_sig_enc,
			"RequestSignatureEncryptedValue": req_sig_enc,
			"SymmetricKeyEncryptedValue": sym_key_enc,
			"Scope": self.scope,
			"TransactionId": txn_id,
			"OAuthTokenValue": "",
			"Id-token-jwt": "",
		}

	def decrypt_medium_with_ds(self, response_json):
		"""Decrypt HDFC 'Medium with DS' response payload:
		1. Decrypt GWSymmetricKeyEncryptedValue using Client Private Key -> 32-byte AES key
		2. Decrypt ResponseSignatureEncryptedValue using AES-256-CBC with fixed IV -> unpad -> strip 16-byte IV
		3. Extract inner payload from JWS (or JSON)
		"""
		gw_sym_key_enc = response_json.get("GWSymmetricKeyEncryptedValue")
		resp_sig_enc = response_json.get("ResponseSignatureEncryptedValue") or response_json.get(
			"ResponseEncryptedValue"
		)

		if not gw_sym_key_enc or not resp_sig_enc:
			return response_json

		priv_pem = self.get_file_content(self.private_key).encode("utf-8")
		rsa_priv_key = RSA.import_key(priv_pem)

		# Decrypt symmetric key
		cipher_rsa_dec = Cipher_PKCS1_v1_5.new(rsa_priv_key)
		decrypted_gw_key = cipher_rsa_dec.decrypt(
			base64.b64decode(gw_sym_key_enc), sentinel=None
		)

		# Decrypt AES ciphertext
		iv = b"1234567890123456"
		cipher_aes_dec = AES.new(decrypted_gw_key, AES.MODE_CBC, iv)
		decrypted_padded = cipher_aes_dec.decrypt(base64.b64decode(resp_sig_enc))
		decrypted_data = unpad(decrypted_padded, 16, style="pkcs7")

		# Skip 16-byte IV prefix
		output_text = decrypted_data[16:].decode("utf-8")

		# If output is JWS (3 parts separated by dot)
		if "." in output_text:
			parts = output_text.split(".")
			if len(parts) >= 2:
				payload_b64 = parts[1]
				rem = len(payload_b64) % 4
				if rem > 0:
					payload_b64 += "=" * (4 - rem)
				return json.loads(
					base64.urlsafe_b64decode(payload_b64).decode("utf-8")
				)

		try:
			return json.loads(output_text)
		except Exception:
			return output_text

	@frappe.whitelist()
	def get_bank_balance(self):
		"""Inquire CASA Account Basic Balance using HDFC Corporate CASA Basic Balance Inquiry API"""
		if hasattr(self, "balance_check") and not self.balance_check:
			frappe.throw(_("Bank Balance Check is not enabled."))

		url = (
			getattr(self.urls, "bank_balance", None)
			or f"{self.base_url.rstrip('/')}/API/Corp_CASABalInq_Basic"
		)
		txn_id = f"BAL{utils.get_id()}"
		self._current_txn_id = txn_id

		payload = self.get_encrypted_payload(method="bank_balance")

		headers = {
			"Content-Type": "application/json",
			"apikey": self.get_password("client_key"),
			"transactionId": txn_id,
			"Accept": "application/json",
		}

		response = requests.post(
			url,
			headers=headers,
			json=payload,
			cert=self.get_cert(),
			proxies=self.get_proxies(),
			timeout=30,
		)

		log_id = create_api_log(
			response,
			action="Bank Balance",
			account_config=self.get_account_config("bank_balance"),
			ref_doctype="Bank Balance",
			ref_docname=self.account_number,
			unique_id=txn_id,
			connector=self,
		)

		return self.get_decrypted_response(
			response, method="bank_balance", log_id=log_id
		)

	def get_balance(self):
		return self.get_bank_balance()

	def parse_statement_gzip_file(self, byte_file):
		"""Decompress base64 encoded gzip statement and parse tilde-separated transactions"""
		try:
			decompressed = gzip.decompress(base64.b64decode(byte_file)).decode("utf-8")
			lines = [l.strip() for l in decompressed.splitlines() if l.strip()]
			if not lines:
				return []

			transactions = []
			for line in lines[1:]:
				cols = line.split("~")
				if len(cols) < 6:
					continue
				txn_date = getdate(cols[0]).strftime("%Y-%m-%d")
				txn_desc = cols[2]
				amt = flt(cols[3])
				dr_cr = cols[4].upper()
				ref_no = cols[5]
				if dr_cr == "D":
					amt = -1 * abs(amt)
				else:
					amt = abs(amt)
				transactions.append({
					"transaction_date": txn_date,
					"transaction_amount": amt,
					"reference_number": ref_no,
					"transaction_description": txn_desc,
				})
			return transactions
		except Exception as e:
			frappe.log_error(f"Error parsing statement gzip: {e}", "HDFC Statement Parse Error")
			return []

	@frappe.whitelist()
	def get_bank_statement(self):
		"""Fetch Account Statement from HDFC Bank (Report_Generation -> InquireReport -> DownloadReport)"""
		if hasattr(self, "statement_fetch") and not self.statement_fetch:
			frappe.throw(_("Bank Statement Fetch is not enabled."))

		base = (self.base_url or "https://api.hdfcbank.com").rstrip("/")
		is_tryitout = "api-tryitout" in base

		if is_tryitout:
			gen_url = f"{base}/API/LargeStatement/Sandbox/Report_Generation"
			inq_url = f"{base}/API/LargeStatement/Sandbox/InquireReport"
			dl_url = f"{base}/API/LargeStatement/Sandbox/DownloadReport"
		else:
			gen_url = getattr(self.urls, "bank_statement", None) or f"{base}/API/Report_Generation"
			inq_url = f"{base}/API/InquireReport"
			dl_url = f"{base}/API/DownloadReport"

		txn_id = f"STMT{utils.get_id()}"
		self._current_txn_id = txn_id
		config = self.get_account_config("bank_statement")

		apikey = (
			"aHNDiZ5fj52HXscBQMBEJwdG3BBNjBNNaeCyKt5ff4DL6RmO"
			if is_tryitout
			else self.get_password("client_key")
		)

		headers = {
			"Content-Type": "application/json",
			"apikey": apikey,
			"transactionId": txn_id,
			"Accept": "application/json",
		}

		if is_tryitout:
			payload = config
			cert = None
		else:
			payload = self.get_encrypted_payload(method="bank_statement")
			cert = self.get_cert()

		response = requests.post(
			gen_url,
			headers=headers,
			json=payload,
			cert=cert,
			proxies=self.get_proxies(),
			timeout=30,
		)

		log_id = create_api_log(
			response,
			action="Bank Statement",
			account_config=config,
			ref_doctype="Bank Statement",
			ref_docname=self.account_number,
			unique_id=txn_id,
			connector=self,
		)

		resp_data = self.get_decrypted_response(
			response, method="bank_statement", log_id=log_id
		)

		user_ref = (
			resp_data.get("userReferencrNumber")
			or resp_data.get("userReferenceNumber")
		)
		if not user_ref and isinstance(resp_data.get("decrypted_data"), dict):
			d = resp_data["decrypted_data"]
			user_ref = d.get("userReferencrNumber") or d.get("userReferenceNumber")

		if user_ref:
			inq_headers = dict(headers)
			inq_payload = {"userReferenceNumber": user_ref}
			inq_res = requests.post(
				inq_url,
				headers=inq_headers,
				json=inq_payload,
				cert=cert,
				proxies=self.get_proxies(),
				timeout=30,
			)

			pag_ref = None
			if inq_res.status_code == 200:
				inq_data = inq_res.json()
				for item in inq_data.get("inquireRptDetailsDTO", []):
					for pag in item.get("paginatedReportsDetailsDTO", []):
						if pag.get("refPaginatedReportNo"):
							pag_ref = pag.get("refPaginatedReportNo")
							break

			if pag_ref:
				dl_headers = dict(headers)
				dl_payload = {"refPaginatedReportNo": pag_ref}
				dl_res = requests.post(
					dl_url,
					headers=dl_headers,
					json=dl_payload,
					cert=cert,
					proxies=self.get_proxies(),
					timeout=30,
				)

				if dl_res.status_code == 200:
					dl_data = dl_res.json()
					byte_file = dl_data.get("byteFile")
					if byte_file:
						txns = self.parse_statement_gzip_file(byte_file)
						resp_data["server_status"] = "Success"
						resp_data["status"] = "SUCCESS"
						resp_data["bank_statements"] = txns
						resp_data["message"] = f"Successfully fetched {len(txns)} transactions"
						resp_data["decrypted_data"] = dl_data

		return resp_data

	@frappe.whitelist()
	def reset_endpoints(self):
		"""Populate default endpoint URLs according to base_url"""
		base = (self.base_url or "https://api.hdfcbank.com").rstrip("/")
		self.base_url = base

		endpoints = [
			{"action": "host", "url": urlparse(base).netloc},
			{"action": "oauth_token", "url": f"{base}/auth/oauth/v1/token"},
			{"action": "make_payment", "url": f"{base}/api/v1/corp-initiatePayment"},
			{"action": "payment_status", "url": f"{base}/api/v1/corp-paymentInq"},
			{"action": "bank_balance", "url": f"{base}/API/Corp_CASABalInq_Basic"},
			{"action": "bank_statement", "url": f"{base}/API/Report_Generation"},
		]
		self.api_endpoints = []
		self.extend("api_endpoints", endpoints)

	def get_transaction_history(self):
		return "Transaction History Not Implemented"

	def get_status_description(self, od_status):
		return {
			"CI": ("Cancel Requested", "Pending"),
			"D": ("Deleted", "Rejected"),
			"EX": ("Expired", "Failed"),
			"IO": ("Pending Additional Approval", "Pending"),
			"LK": ("Parked", "Pending"),
			"RA": ("Pending Approval", "Pending"),
			"RE": ("Rejected by Entitlement", "Rejected"),
			"RN": ("Rule Setup Required", "Pending"),
			"RO": ("Rejected by Verifier / Approver", "Rejected"),
			"RR": ("Pending Release", "Pending"),
			"RV": ("Pending Verification", "Pending"),
			"TXBVSU": ("Transaction Business Validation Successful", "Pending"),
			"TXCOMP": ("Payment Completed", "Processed"),
			"TXDBPR": ("Debit in progress", "Pending"),
			"TXPDST": ("Pending for Settlement", "Processed"),
			"TXREJE": ("Payment Rejected", "Rejected"),
			"TXVLSU": ("Processed", "Processed"),
			"TXWRHD": ("Payment Warehoused", "Pending"),
			"TXAWRB": ("Transaction Awaiting Rebulking", "Pending"),
			"TXEXPD": ("Transaction Expired", "Failed"),
			"611081": (
				"Transaction Expired: The requested transaction doesnot follow 7 day criteria",
				"Failed",
			),
			"TXSIP": ("Settlement in Progress", "Pending"),
			"DEBFL": ("Debit Failed", "Failed"),
			"DEBREJE": ("Debit Rejected", "Rejected"),
			"MANREJE": ("Manually Rejected", "Rejected"),
		}.get(od_status, (f"{od_status} Description Not Available", ""))
