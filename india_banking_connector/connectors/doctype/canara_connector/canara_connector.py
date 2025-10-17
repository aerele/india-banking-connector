# Copyright (c) 2025, Vintrosys Business Solutions and contributors
# For license information, please see license.txt

import json
from base64 import b64encode

import frappe
import requests
import uuid, time   
from typing import Optional


from india_banking_connector.connectors.bank_connector import BankConnector
from india_banking_connector.india_banking_connector.doctype.bank_request_log.bank_request_log import (
	create_api_log,
)

class CanaraConnector(BankConnector):
	bank = "Canara Bank"

	__all__ = ["initiate_payment", "initiate_batch_payment"]

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		self.bulk_transaction = kwargs.get("bulk_transaction")
		self.doc = frappe._dict(kwargs.get("doc", {}))
		self.payment_doc = frappe._dict(kwargs.get("payment_doc", {}))

	@property
	def urls(self):		
		return super().urls

	def headers(self) -> dict:
		
		headers = {
			"x-client-id": self.client_key,
			"x-client-secret": self.client_secret,
			"x-client-certificate": self.cert_file,
			"x-api-interaction-id": f"erp-{uuid.uuid4().hex}",
			"x-timestamp": str(int(time.time())),
			"Content-Type": "application/json",
			# x-signature will be set per request			
		}
		
		ip = self.ip_address
		if ip:
			headers["x-forwarded-for"] = ip
		return headers

	def _sign_payload(self, plain_text: str) -> str:
		
		pk_pem = self.private_key
		if not pk_pem:
			frappe.throw("Private key not configured for Canara Connector")

		private_key = serialization.load_pem_private_key(
			pk_pem.encode("utf-8"), password=None, backend=default_backend()
		)

		signature = private_key.sign(
			plain_text.encode("utf-8"),
			asym_padding.PKCS1v15(),
			hashes.SHA256(),
		)
		return b64encode(signature).decode("utf-8")

	def _jwe_encrypt(self, plaintext: str) -> str:
		
		hex_key = self.symmetric_key
		if not hex_key:
			frappe.throw("Symmetric key (hex) not configured for Canara Connector")

		key_bytes = bytes.fromhex(hex_key)
		k_b64u = b64encode(key_bytes).decode("utf-8").rstrip("=")
		jwk_oct = jwk.JWK(kty="oct", k=k_b64u)

		jwetoken = jwe.JWE(plaintext.encode("utf-8"), json_encode={"alg": "A256KW", "enc": "A128CBC-HS256"})
		jwetoken.add_recipient(jwk_oct)
		compact = jwetoken.serialize(compact=True)
		return compact

	def _jwe_decrypt(self, compact_jwe: str) -> str:
		"""
		Decrypt JWE compact string using the symmetric key (hex)
		"""
		hex_key = self.symmetric_key
		if not hex_key:
			frappe.throw("Symmetric key not configured for Canara Connector")

		key_bytes = bytes.fromhex(hex_key)
		k_b64u = b64encode(key_bytes).decode("utf-8").rstrip("=")
		jwk_oct = jwk.JWK(kty="oct", k=k_b64u)

		token = jwe.JWE()
		token.deserialize(compact_jwe)
		token.decrypt(jwk_oct)
		return token.payload.decode("utf-8")


	def _batch_payment_payload(self) -> str:
		"""
		Build the batch payload (as per sample). Return compact JSON string.
		"""
		payment = self.payment_doc if not self.bulk_transaction else self.doc

		auth_user = self.get_password("user_name") or ""
		auth_pass = self.get_password("password") or ""
		auth_b64 = "Basic " + b64encode(f"{auth_user}:{auth_pass}".encode()).decode()

		txn_list = []
		
		txns = payment.get("transactions") or [payment]

		for t in txns:
			txn = {
				"TxnRefNo": t.get("txn_ref_no", t.name),
				"DrAcct": self.account_number,
				"SndrNm": t.get("sender_name", getattr(self, "company_name", "")),
				"TxnAmt": str(t.get("amount", t.get("txn_amount", 0))),
				"TxnType": t.get("txn_type", "N06"),
				"BenefIFSC": t.get("ifsc_code", t.get("benef_ifsc")),
				"BenefAcNo": t.get("bank_account_no", t.get("benef_ac_no")),
				"BenefAcNm": t.get("party", t.get("benef_name")),
				"Nrtv": t.get("remarks", ""),
			}
			txn_list.append(txn)

		payload= {
				"Authorization": auth_b64,
				"ExternalReferenceNo": payment.get("external_reference_no", payment.name),
				"TotAmt": str(payment.get("total_amount", sum([float(x["TxnAmt"]) for x in txn_list]))),
				"TxnCnt": str(len(txn_list)),
				"DatTxn": frappe.utils.nowdate().replace("-", ""),
				"BatchRequestID": payment.get("batch_request_id", f"{self.bank[:3].upper()}{payment.name[:12]}"),
				"TxnDtls": {"Txn": txn_list},
			}
			
		return json.dumps(payload, separators=(",", ":"))

	def initiate_batch_payment(self):
		payment_details = self.payment_doc if not self.bulk_transaction else self.doc
		unique_id = payment_details.name

		if existing := self.validate_duplicate_payments(unique_id=unique_id):
			return existing

		payload_to_encrypt = self._batch_payment_payload()
		payload_to_sign = {
							"Request": {
								"body": {
										"encryptData": 
											payload_to_encrypt
										}
								}
							}
		signature_b64 = self._sign_payload(payload_to_sign)
		encrypted_compact = self._jwe_encrypt(payload_to_encrypt)

		final_body = {"Request": {"body": {"encryptData": encrypted_compact}}}
		headers = self.headers
		headers["x-signature"] = signature_b64

		url = getattr(self.urls, "batch_payment", None) or getattr(self.urls, "make_payment", None)
		if not url:
			frappe.throw("Canara batch payment endpoint not configured in Endpoint URLs")

		response = requests.post(url, headers=headers, json=final_body, timeout=120)

		log_id = create_api_log(
			response,
			action="Initiate Batch Payment",
			account_config=payload_to_sign,
			ref_doctype=payment_details.parenttype or payment_details.doctype,
			ref_docname=payment_details.parent or payment_details.name,
			unique_id=unique_id,
		)

		return self._handle_response(response, log_id=log_id)


	def _handle_response(self, response: requests.Response, log_id: Optional[str] = None):
		
		res = frappe._dict({})
		if not response.ok:
			res.update({"status": "Request Failure", "error": response.text})
			return res

		try:
			resp_json = response.json()
		except Exception:
			res.update({"status": "Invalid Response", "error": response.text})
			return res

		try:
			enc = resp_json.get("Response", {}).get("body", {}).get("encryptData")
			if enc:
				
				decrypted_text = self._jwe_decrypt(enc)
				
				decrypted_json = json.loads(decrypted_text)
				
				resp_json["Response"]["body"]["decrypted"] = decrypted_json

				
				if log_id and frappe.db.exists("Bank Request Log", log_id):
					frappe.db.set_value("Bank Request Log", log_id, "decrypted_response", json.dumps(decrypted_json))
			else:
				# no encryptData present; nothing to decrypt
				pass
		except Exception as e:
			# decryption failure: log and return raw
			frappe.log_error(title="Canara Decrypt Error", message=frappe.get_traceback())
			res.update({"status": "Decryption Failed", "error": str(e), "raw_response": resp_json})
			return res

		decrypted_body = resp_json.get("Response", {}).get("body", {}).get("decrypted")
		if decrypted_body:
			encdata = decrypted_body.get("encryptData", decrypted_body)  
			
			if isinstance(encdata, dict) and encdata.get("ErrorCode"):
				res.update({"status": "FAILED", "message": encdata.get("ErrorDesc"), "data": encdata})
			else:
				res.update({"status": "SUCCESS", "data": encdata})
		else:
			
			res.update({"status": "SUCCESS", "data": resp_json})

		return res

