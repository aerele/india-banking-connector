
import json
import base64
import uuid
import datetime
import traceback
import re

from frappe.utils import flt, getdate

import frappe
import requests
from jose import jwe
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

from india_banking_connector.connectors.bank_connector import BankConnector
from india_banking_connector.india_banking_connector.doctype.bank_request_log.bank_request_log import (
	create_api_log,
)


class CanaraBankConnector(BankConnector):
	bank = "Canara Bank"

	__all__ = ["initiate_payment", "get_payment_status", "get_bank_balance"]

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.bulk_transaction = kwargs.get("bulk_transaction")
		self.doc = frappe._dict(kwargs.get("doc", {}))
		self.payment_doc = frappe._dict(kwargs.get("payment_doc", {}))

	def is_mock_mode(self):
		"""
		Check if the connector should run in mock simulation mode.
		Returns True if testing is enabled and credentials or certificates are dummy placeholders.
		"""
		if not self.testing:
			return False

		client_id = self.get_password("client_id")
		return (
			not self.private_key
			or "dummy" in (self.private_key or "").lower()
			or not self.client_certificate
			or "dummy" in (self.client_certificate or "").lower()
			or client_id in ["DUMMY_CLIENT_ID", "123", "dummy", ""]
		)

	@property
	def headers(self):
		headers_dict = {
			"x-client-id": self.get_password("client_id"),
			"x-Client-Secret": self.get_password("client_secret"),
			"x-api-interaction-id": str(uuid.uuid4()),
			"x-timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
			"Content-Type": "application/json",
			"Cookie": "API",
			"x-forwarded-for": getattr(frappe.local, "request_ip", "127.0.0.1")
		}
		
		if self.client_certificate:
			headers_dict["x-client-Certificate"] = self.get_client_certificate_content()
			
		return headers_dict

	def get_client_certificate_content(self):
		file_path = self.get_file_relative_path(self.client_certificate)
		with open(file_path, 'r') as f:
			cert_data = f.read().replace('-----BEGIN CERTIFICATE-----', '').replace('-----END CERTIFICATE-----', '').replace('\n', '').strip()
		return cert_data

	def sign_payload(self, plaintext_json):
		if not self.private_key:
			frappe.throw("RSA Private Key is missing in Canara Bank Connector")
		
		file_path = self.get_file_relative_path(self.private_key)
		with open(file_path, "rb") as key_file:
			private_key = serialization.load_pem_private_key(
				key_file.read(),
				password=None,
				backend=default_backend()
			)
			
		signature = private_key.sign(
			plaintext_json.encode('utf-8'),
			padding.PKCS1v15(),
			hashes.SHA256()
		)
		return base64.b64encode(signature).decode('utf-8')

	def encrypt_payload(self, encrypt_data_dict):
		symmetric_key_str = self.get_password("symmetric_key").strip()
		if not symmetric_key_str:
			frappe.throw("Symmetric Key is missing in Canara Bank Connector")
			
		try:
			key_bytes = bytes.fromhex(symmetric_key_str)
		except Exception:
			key_bytes = symmetric_key_str.encode('utf-8')
			
		key_bytes = key_bytes[:32].ljust(32, b'\0')

		protected_header = {
			"alg": "A256KW",
			"enc": "A128CBC-HS256"
		}
		
		plaintext = json.dumps(encrypt_data_dict, separators=(',', ':'))
		encrypted_jwe = jwe.encrypt(
			plaintext,
			key_bytes,
			algorithm=protected_header["alg"],
			encryption=protected_header["enc"]
		)
		return encrypted_jwe.decode('utf-8') if isinstance(encrypted_jwe, bytes) else encrypted_jwe

	def get_ib_auth(self):
		ib_user = self.get_password("ib_username")
		ib_pwd = self.get_password("ib_encrypted_password")
		auth_str = f"{ib_user}:{ib_pwd}"
		return "Basic " + base64.b64encode(auth_str.encode('utf-8')).decode('utf-8')

	def initiate_payment(self):
		if self.bulk_transaction:
			return self.initiate_batch_payment()

		payment_details = self.payment_doc
		unique_id = re.sub(r'[^A-Za-z0-9]', '', payment_details.name)[:20]

		if self.is_mock_mode():
			utr = f"CNRB{uuid.uuid4().hex[:10].upper()}"
			return frappe._dict({
				"payment_status": "ACCEPTED",
				"message": "Payment Accepted (Mocked)",
				"summary_details": {
					payment_details.name: {
						"payment_status": "Accepted",
						"message": "Success (Mocked)",
						"utr_number": utr
					}
				}
			})

		if existing_payment_response := self.validate_duplicate_payments(unique_id=unique_id):
			return existing_payment_response

		url = self.urls.make_payment
		
		mode_of_transfer = payment_details.mode_of_transfer
		if "A2A" in mode_of_transfer or "Internal" in mode_of_transfer:
			mode_of_transfer = "IFT"
			
		encrypt_data = {
			"Authorization": self.get_ib_auth(),
			"key": "",
			"customerID": self.customer_id,
			"srcAcctNumber": self.account_number,
			"txnPassword": self.get_password("txn_password"),
			"branchCode": self.branch_code,
			"destAcctNumber": payment_details.bank_account_no,
			"ifscCode": payment_details.branch_code,
			"txnAmount": str(payment_details.amount),
			"benefName": payment_details.party_name or payment_details.party,
			"userRefNo": unique_id,
			"narration": (payment_details.get("narration") or "Payment")[:35],
			"valueDate": frappe.utils.getdate().strftime("%d-%m-%Y"),
			"TrnType": mode_of_transfer
		}
		
		plaintext_json_request = json.dumps({
			"Request": {
				"body": {
					"encryptData": encrypt_data
				}
			}
		}, separators=(',', ':'))
		
		req_headers = self.headers
		req_headers["x-signature"] = self.sign_payload(plaintext_json_request)
		
		final_payload = {
			"Request": {
				"body": {
					"encryptData": self.encrypt_payload(encrypt_data)
				}
			}
		}

		try:
			response = requests.post(url, headers=req_headers, json=final_payload, verify=False)
		except Exception as e:
			frappe.log_error("Canara Bank Connection Error", frappe.get_traceback())
			return {"status": "Request Failure", "message": str(e)}

		log_id = create_api_log(
			response,
			action="Initiate Payment",
			account_config=plaintext_json_request,
			ref_doctype=payment_details.parenttype or payment_details.doctype,
			ref_docname=payment_details.parent or payment_details.name,
			unique_id=unique_id,
		)

		return self.get_verified_response(response, method="make_payment", log_id=log_id)

	def get_verified_response(self, response, method, log_id=None):
		res_dict = frappe._dict({})
		
		has_encrypt_data = False
		response_json = {}
		try:
			response_json = response.json()
			encrypt_data_str = response_json.get("Response", {}).get("body", {}).get("encryptData", "")
			if not encrypt_data_str:
				encrypt_data_str = response_json.get("Response", {}).get("encryptData", "")
			if encrypt_data_str:
				has_encrypt_data = True
		except Exception:
			pass

		if not response.ok and not has_encrypt_data:
			res_dict.update({"status": "Request Failure", "error": response.text})
			return res_dict

		try:
			if not response_json:
				response_json = response.json()
			
			encrypt_data_str = response_json.get("Response", {}).get("body", {}).get("encryptData", "")
			if not encrypt_data_str:
				encrypt_data_str = response_json.get("Response", {}).get("encryptData", "")
				
			if not encrypt_data_str:
				res_dict.update({"status": "Request Failure", "error": "No encryptData in response"})
				return res_dict
				
			decrypted_json = self.decrypt_payload(encrypt_data_str)
			
			if log_id and frappe.db.exists("Bank Request Log", log_id):
				frappe.db.set_value("Bank Request Log", log_id, "decrypted_response", json.dumps(decrypted_json))
				
			self.format_response_dict(decrypted_json, res_dict, method)
		except Exception as e:
			frappe.log_error("Canara Bank Decryption Error", frappe.get_traceback())
			res_dict.update({"status": "Request Failure", "error": str(e)})
			
		return res_dict

	def format_response_dict(self, data, res_dict, method):
		data = frappe._dict(data)
		
		if method == "make_payment":
			metadata = data.get("metadata", {}).get("status", {})
			code = metadata.get("code")
			
			if code == "200" or data.get("txnMessages"):
				utr = data.get("utr", "")
				res_dict.payment_status = "ACCEPTED"
				res_dict.message = "Payment Accepted"
				res_dict.summary_details = {
					self.payment_doc.name: {
						"payment_status": "Accepted",
						"message": metadata.get("desc", "Success"),
						"utr_number": utr
					}
				}
			else:
				err_msg = data.get("ErrorResponse", {}).get("ErrorMessage", "Payment Failed")
				res_dict.payment_status = "FAILED"
				res_dict.summary_details = {
					self.payment_doc.name: {
						"payment_status": "Failed",
						"message": err_msg
					}
				}

		elif method == "payment_status":
			res_dict.payment_status = "PROCESSED"
			status_code = ""
			utr = ""
			
			if "TXNSTATUS" in data:
				status_code = data.get("TXNSTATUS", {}).get("TxnStatus", "")
				utr = data.get("TXNSTATUS", {}).get("UTR", "")
			else:
				status_code = data.get("status", "")
				utr = data.get("paymentId", "")
				
			sts = "Pending"
			if "00" in status_code or "Successful" in status_code:
				sts = "Processed"
			elif "20" in status_code or "In Progress" in status_code:
				sts = "Pending"
			elif "40" in status_code or "Failed" in status_code or "42" in status_code:
				sts = "Failed"
				
			res_dict.summary_details = {
				self.payment_doc.name: {
					"status": sts,
					"message": status_code,
					"utr_number": utr,
				}
			}

		elif method == "bank_balance":
			balance = data.get("balAvailable", data.get("currentBalance", "0.00"))
			res_dict.update({
				"balance": balance,
				"current_balance": data.get("currentBalance", ""),
				"available_balance": data.get("balAvailable", ""),
				"hold_amount": data.get("holdAmount", ""),
				"net_balance": data.get("netBalance", ""),
				"customer_name": data.get("customerName", ""),
			})

		elif method == "batch_payment":
			if "response" in data and (data.response.get("TRANSACTION_REF_NO") or data.response.get("batchReferenceNo")):
				txn_ref_no = data.response.get("TRANSACTION_REF_NO") or data.response.get("batchReferenceNo")
				res_dict.payment_status = "ACCEPTED"
				res_dict.message = data.response.get("result", {}).get("rdesc", "Batch Accepted — Awaiting Checker Approval")
				res_dict.file_sequence_number = txn_ref_no
				summary_details = {}
				for summary in self.doc.get("summary", []):
					summary_details[summary.get("name")] = {
						"payment_status": "Accepted",
						"message": "Batch accepted, pending checker approval",
						"utr_number": ""
					}
				res_dict.summary_details = summary_details
			else:
				err_desc = data.get("Desc", data.get("ErrorDesc", "Batch Initiation Failed"))
				res_dict.payment_status = "FAILED"
				res_dict.message = err_desc
				summary_details = {}
				for summary in self.doc.get("summary", []):
					summary_details[summary.get("name")] = {
						"payment_status": "Failed",
						"message": err_desc,
					}
				res_dict.summary_details = summary_details

		elif method == "batch_status":
			summary_details = {}
			bulk_response = data.get("bulkResponse", {})
			txn_list = bulk_response.get("bulkRefDet", []) if bulk_response else []
			if not txn_list:
				err_desc = data.get("ErrorDesc", data.get("Desc", "No Status Found"))
				res_dict.payment_status = "FAILED"
				res_dict.message = err_desc
				return
			for txn in txn_list:
				txn = frappe._dict(txn)
				txn_ref = txn.get("txnRefNo", "")
				status = txn.get("status", "")
				trn_status = txn.get("trnStatus", "")
				utr = txn.get("externalReferenceId", "")
				reason = txn.get("reason", "")
				sts = "Pending"
				if status == "VERIFIED":
					sts = "Pending"
				elif status == "COMPLETED":
					if "00" in trn_status or "Successful" in trn_status:
						sts = "Processed"
					elif "20" in trn_status or "In Progress" in trn_status:
						sts = "Pending"
					elif "40" in trn_status or "Failed" in trn_status or "42" in trn_status:
						sts = "Failed"
				elif status in ["Rejected", "Expired", "Error"]:
					sts = "Failed"
				summary_details[txn_ref] = {
					"status": sts,
					"message": trn_status or status,
					"utr_number": utr,
					"reason": reason
				}
			res_dict.payment_status = "PROCESSED"
			res_dict.summary_details = summary_details

	def decrypt_payload(self, encrypted_jwe_str):
		symmetric_key_str = self.get_password("symmetric_key").strip()
		try:
			key_bytes = bytes.fromhex(symmetric_key_str)
		except Exception:
			key_bytes = symmetric_key_str.encode('utf-8')
			
		key_bytes = key_bytes[:32].ljust(32, b'\0')

		decrypted = jwe.decrypt(encrypted_jwe_str, key_bytes)
		return json.loads(decrypted)

	def get_payment_status(self):
		if self.bulk_transaction:
			return self.get_batch_status()

		payment_details = self.payment_doc
		unique_id = re.sub(r'[^A-Za-z0-9]', '', payment_details.name)[:20]

		if self.is_mock_mode():
			utr = payment_details.get("reference_number") or f"CNRB{uuid.uuid4().hex[:10].upper()}"
			return frappe._dict({
				"payment_status": "PROCESSED",
				"summary_details": {
					payment_details.name: {
						"status": "Processed",
						"message": "Successful (Mocked)",
						"utr_number": utr
					}
				}
			})

		mode_of_transfer = payment_details.mode_of_transfer
		if "A2A" in mode_of_transfer or "Internal" in mode_of_transfer:
			mode_of_transfer = "IFT"

		if mode_of_transfer in ["NEFT", "RTGS"]:
			url = self.urls.payment_status
			encrypt_data = {
				"Authorization": self.get_ib_auth(),
				"key": "",
				"userRefNo": unique_id,
				"TrnType": mode_of_transfer,
				"customerID": self.customer_id,
				"UTR": payment_details.get("reference_number", "")
			}
			plaintext_json_request = json.dumps({"Request": {"body": {"encryptData": encrypt_data}}}, separators=(',', ':'))
			final_payload = {"Request": {"body": {"encryptData": self.encrypt_payload(encrypt_data)}}}
		else:
			url = getattr(self.urls, "payment_status_imps", "")
			encrypt_data = {
				"Authorization": self.get_ib_auth(),
				"key": "",
				"customerID": self.customer_id
			}
			plaintext_json_request = json.dumps({"Request": {"body": {"userRefNumber": unique_id, "encryptData": encrypt_data}}}, separators=(',', ':'))
			final_payload = {"Request": {"body": {"userRefNumber": unique_id, "encryptData": self.encrypt_payload(encrypt_data)}}}

		req_headers = self.headers
		req_headers["x-signature"] = self.sign_payload(plaintext_json_request)
		
		try:
			response = requests.post(url, headers=req_headers, json=final_payload, verify=False)
		except Exception as e:
			frappe.log_error("Canara Bank Status Error", frappe.get_traceback())
			return {"status": "Request Failure", "message": str(e)}

		create_api_log(
			response,
			action="Payment Status",
			account_config=plaintext_json_request,
			ref_doctype=payment_details.parenttype or payment_details.doctype,
			ref_docname=payment_details.parent or payment_details.name,
			unique_id=unique_id,
		)

		return self.get_verified_response(response, method="payment_status")

	def get_bank_balance(self):
		if self.is_mock_mode():
			return frappe._dict({
				"balance": "5000000.00",
				"current_balance": "5000000.00",
				"available_balance": "5000000.00",
				"hold_amount": "0.00",
				"net_balance": "5000000.00",
				"customer_name": "AALADIPATTIYAN PRIVATE LIMITED"
			})

		url = getattr(self.urls, "bank_balance", "")
		encrypt_data = {
			"Authorization": self.get_ib_auth(),
			"acctNumber": self.account_number,
			"customerID": self.customer_id
		}
		plaintext_json_request = json.dumps({
			"Request": {
				"body": {
					"branchCode": self.branch_code,
					"encryptData": encrypt_data
				}
			}
		}, separators=(',', ':'))
		
		final_payload = {
			"Request": {
				"body": {
					"branchCode": self.branch_code,
					"encryptData": self.encrypt_payload(encrypt_data)
				}
			}
		}

		req_headers = self.headers
		req_headers["x-signature"] = self.sign_payload(plaintext_json_request)
		
		try:
			response = requests.post(url, headers=req_headers, json=final_payload, verify=False)
		except Exception as e:
			return {"status": "Request Failure", "message": str(e)}

		create_api_log(
			response,
			action="Bank Balance",
			account_config=plaintext_json_request,
			ref_doctype="Bank Account",
			ref_docname=self.account_number,
		)

		return self.get_verified_response(response, method="bank_balance")

	def initiate_batch_payment(self):
		"""Canara Bank Batch push-maker + batch-initiation flow."""
		doc = self.doc
		batch_id = re.sub(r'[^A-Za-z0-9]', '', doc.name)[:50]

		if self.is_mock_mode():
			batch_ref_no = f"CANBATCH{uuid.uuid4().hex[:10].upper()}"
			return frappe._dict({
				"payment_status": "ACCEPTED",
				"message": "Batch Accepted (Mocked) — Awaiting Checker Approval",
				"file_sequence_number": batch_ref_no,
				"summary_details": {
					summary.get("name"): {
						"payment_status": "Accepted",
						"message": "Batch accepted, pending checker approval (Mocked)",
						"utr_number": ""
					} for summary in doc.get("summary", [])
				}
			})

		ext_ref = re.sub(r'[^A-Za-z0-9]', '', str(uuid.uuid4().hex))[:30]

		transactions = []
		total_amount = 0

		for summary in doc.get("summary", []):
			summary = frappe._dict(summary)
			if summary.get("payment_initiated") or summary.get("payment_status") != "Pending":
				continue

			mode = summary.get("mode_of_transfer", "NEFT")
			if "A2A" in mode or "Internal" in mode or mode == "IFT":
				mode_code = "INT"
			elif mode == "IMPS":
				mode_code = "IFS"
			elif mode == "RTGS":
				mode_code = "R41"
			else:
				mode_code = "N06"

			txn_ref = re.sub(r'[^A-Za-z0-9]', '', summary.name)[:25]
			txn_amount = flt(summary.amount, 2)
			total_amount += txn_amount

			transactions.append({
				"TxnRefNo": txn_ref,
				"DrAcct": self.account_number,
				"SndrNm": re.sub(r'[^A-Za-z0-9 ]', '', doc.get("company_bank_account_name", "SENDER"))[:35],
				"TxnAmt": f"{txn_amount:.2f}",
				"TxnType": mode_code,
				"BenefIFSC": summary.get("branch_code", "") or "",
				"BenefAcNo": summary.get("bank_account_no", ""),
				"BenefAcNm": re.sub(r'[^A-Za-z0-9 ]', '', summary.get("party_name", "") or summary.get("party", ""))[:35],
				"Nrtv": re.sub(r'[^A-Za-z0-9 ]', '', summary.get("narration", "") or "Payment")[:35]
			})

		if not transactions:
			return {"payment_status": "FAILED", "message": "No pending transactions found"}

		push_encrypt_data = {
			"Authorization": self.get_ib_auth(),
			"ExternalReferenceNo": ext_ref,
			"TotAmt": f"{total_amount:.2f}",
			"TxnCnt": str(len(transactions)),
			"DatTxn": getdate().strftime("%Y%m%d"),
			"BatchRequestID": batch_id,
			"TxnDtls": {
				"Txn": transactions
			}
		}

		push_url = self.urls.get("batch_push_maker", "")
		if not push_url:
			return {"payment_status": "FAILED", "message": "Batch Push-Maker URL not configured"}

		plaintext_push = json.dumps({"Request": {"body": {"encryptData": push_encrypt_data}}}, separators=(',', ':'))
		final_push_payload = {"Request": {"body": {"encryptData": self.encrypt_payload(push_encrypt_data)}}}

		req_headers = self.headers
		req_headers["x-signature"] = self.sign_payload(plaintext_push)

		try:
			push_response = requests.post(push_url, headers=req_headers, json=final_push_payload, verify=False)
		except Exception as e:
			frappe.log_error("Canara Bank Push-Maker Error", frappe.get_traceback())
			return {"payment_status": "FAILED", "message": f"Push-Maker failed: {str(e)}"}

		create_api_log(
			push_response,
			action="Batch Push Maker",
			account_config=plaintext_push,
			ref_doctype="Payment Order",
			ref_docname=doc.name,
			unique_id=batch_id,
		)

		if not push_response.ok:
			return {"payment_status": "FAILED", "message": f"Push-Maker HTTP Error: {push_response.text}"}

		try:
			push_res_json = push_response.json()
			push_encrypt_str = push_res_json.get("Response", {}).get("body", {}).get("encryptData", "")
			if not push_encrypt_str:
				push_encrypt_str = push_res_json.get("Response", {}).get("encryptData", "")
			if not push_encrypt_str:
				return {"payment_status": "FAILED", "message": "Push-Maker response missing encryptData"}

			push_decrypted = self.decrypt_payload(push_encrypt_str)
		except Exception as e:
			return {"payment_status": "FAILED", "message": f"Push-Maker Decryption Error: {str(e)}"}

		if "ErrorCode" in push_decrypted and push_decrypted.get("ErrorCode") != "0":
			return {
				"payment_status": "FAILED",
				"message": push_decrypted.get("ErrorDesc", "Push-Maker failed validation at Bank")
			}

		init_encrypt_data = {
			"Authorization": self.get_ib_auth(),
			"TFAPassword": self.get_password("txn_password"),
			"customerID": self.customer_id,
			"BatchRequestID": batch_id
		}

		init_url = self.urls.get("batch_initiation", "")
		if not init_url:
			return {"payment_status": "FAILED", "message": "Batch Initiation URL not configured"}

		plaintext_init = json.dumps({"Request": {"body": {"encryptData": init_encrypt_data}}}, separators=(',', ':'))
		final_init_payload = {"Request": {"body": {"encryptData": self.encrypt_payload(init_encrypt_data)}}}

		req_headers = self.headers
		req_headers["x-signature"] = self.sign_payload(plaintext_init)

		try:
			init_response = requests.post(init_url, headers=req_headers, json=final_init_payload, verify=False)
		except Exception as e:
			frappe.log_error("Canara Bank Batch Initiation Error", frappe.get_traceback())
			return {"payment_status": "FAILED", "message": f"Batch Initiation failed: {str(e)}"}

		log_id = create_api_log(
			init_response,
			action="Batch Payment",
			account_config=plaintext_init,
			ref_doctype="Payment Order",
			ref_docname=doc.name,
			unique_id=batch_id,
		)

		return self.get_verified_response(init_response, method="batch_payment", log_id=log_id)

	def get_batch_status(self):
		"""Canara Bank Batch Status Check API."""
		doc = self.doc
		batch_id = re.sub(r'[^A-Za-z0-9]', '', doc.name)[:50]

		if self.is_mock_mode():
			summary_details = {}
			for summary in doc.get("summary", []):
				utr = f"CNRBM{uuid.uuid4().hex[:10].upper()}"
				summary_details[re.sub(r'[^A-Za-z0-9]', '', summary.get("name"))[:25]] = {
					"status": "Processed",
					"message": "Successful",
					"utr_number": utr,
					"reason": "Mocked Success"
				}
			return frappe._dict({
				"payment_status": "PROCESSED",
				"message": "COMPLETED",
				"summary_details": summary_details
			})

		encrypt_data = {
			"Authorization": self.get_ib_auth(),
			"TFAPassword": self.get_password("txn_password"),
			"customerID": self.customer_id,
			"transactionRefNo": doc.get("file_sequence_number", "")
		}

		url = self.urls.get("batch_status", "")
		if not url:
			return {"payment_status": "FAILED", "message": "Batch Status URL not configured"}

		plaintext_json_request = json.dumps({"Request": {"body": {"encryptData": encrypt_data}}}, separators=(',', ':'))
		final_payload = {"Request": {"body": {"encryptData": self.encrypt_payload(encrypt_data)}}}

		req_headers = self.headers
		req_headers["x-signature"] = self.sign_payload(plaintext_json_request)

		try:
			response = requests.post(url, headers=req_headers, json=final_payload, verify=False)
		except Exception as e:
			return {"payment_status": "FAILED", "message": str(e)}

		log_id = create_api_log(
			response,
			action="Batch Status",
			account_config=plaintext_json_request,
			ref_doctype="Payment Order",
			ref_docname=doc.name,
			unique_id=batch_id,
		)

		return self.get_verified_response(response, method="batch_status", log_id=log_id)
