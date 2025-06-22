# Copyright (c) 2024, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

import base64
import xml.etree.ElementTree as ET

import frappe
import requests
from frappe.utils import cstr, getdate, get_datetime

from india_banking_connector.connectors.bank_connector import BankConnector
from india_banking_connector.india_banking_connector.doctype.bank_request_log.bank_request_log import (
	create_api_log,
)
from india_banking_connector.utils import get_id
import json
class KotakMahindraConnector(BankConnector):
	bank = "Kotak Mahindra Bank"

	IV = "0000000000000000".encode("utf-8")

	__all__ = ["intiate_payment", "get_payment_status", "update_beneficiary_details"]

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		self.bulk_transaction = kwargs.get("bulk_transaction")
		self.doc = frappe._dict(kwargs.get("doc", {}))
		self.payment_doc = frappe._dict(kwargs.get("payment_doc", {}))

	def is_active(self):
		if not self.active:
			frappe.throw("Connector not active. Please contact admin.")

	@property
	def urls(self):
		if self.bulk_transaction:
			frappe.throw("Bulk transactions are not Tested")

		base_url = (
			"https://apigwuat.kotak.com:8443"
			if self.testing
			else "https://apigw.kotak.com:8446"
		)
		return frappe._dict(
			{
				"oauth_token": f"{base_url}/auth/oauth/v2/token",
				"make_payment": f"{base_url}/v1/cms/pay",
				"payment_status": f"{base_url}/v1/cms/rev",
				"bank_statement": f"{base_url}/Acc_Stmt_Inq",
				"beneficiary": {
					"Submit": f"{base_url}/beneadd",
					"Update": f"{base_url}/benemod",
					"Discard": f"{base_url}/benedisc",
					"Status": f"{base_url}/benestat",
				}
			}
		)

	@property
	def headers(self):
		return {
			"Content-Type": "application/xml",
			"Authorization": "Bearer " + self.get_oauth_token(),
		}

	def validate_action(self, action):
		if action not in ("Submit", "Update", "Discard", "Approve", "Reject", "Suspend"):
			frappe.throw(frappe._("Invalid Action"))

		if action in ("Approve", "Reject", "Suspend"):
			action = "Status"

		return action

	def intiate_payment(self):
		self.update_client_credentials()

		payment_details = self.payment_doc if not self.bulk_transaction else self.doc

		url = self.urls.make_payment
		headers = self.headers
		payload = self.get_account_config("make_payment")

		encrypted_payload = self.aes_encrypt(
			payload, self.client_secret
		)

		response = requests.post(url, headers=headers, data=encrypted_payload)

		log_id = create_api_log(
			response,
			action="Initiate Payment",
			account_config= payload,
			ref_doctype=payment_details.parenttype or payment_details.doctype,
			ref_docname=payment_details.parent or payment_details.name,
		)

		return self.get_decrypted_response(
			response, method="make_payment", log_id=log_id
		)

	def get_payment_status(self):
		self.action = "payment_status"
		self.update_client_credentials()

		payment_details = self.payment_doc if not self.bulk_transaction else self.doc

		url = self.urls.payment_status
		headers = self.headers
		payload = self.get_account_config("payment_status")
		encrypted_payload = self.aes_encrypt(
			payload, self.client_secret
		)

		response = requests.post(url, headers=headers, data=encrypted_payload)

		log_id = create_api_log(
			response,
			action="Payment Status",
			account_config= payload,
			ref_doctype=payment_details.parenttype or payment_details.doctype,
			ref_docname=payment_details.parent or payment_details.name,
		)

		return self.get_decrypted_response(
			response, method="payment_status", log_id=log_id
		)

	def get_bank_statement(self):
		self.update_client_credentials(action="Statement")

		url = self.urls.bank_statement
		headers = self.headers
		payload = self.get_account_config("bank_statement")

		encrypted_payload = self.aes_encrypt(
			payload, self.client_secret
		)

		response = requests.post(url, headers=headers, data=encrypted_payload)

		log_id = create_api_log(
			response,
			action="Bank Statement",
			account_config= payload,
			ref_doctype="Bank Statement",
			ref_docname=self.account_number,
		)

		return self.get_decrypted_response(
			response, method="bank_statement", log_id=log_id
		)

	def update_beneficiary_details(self):
		payment_doc = self.payment_doc

		action = self.validate_action(payment_doc.action)
		self.update_client_credentials(action=action)

		url = self.urls.beneficiary[action]
		params = {"access_token": self.get_oauth_token()}
		headers = {"Content-Type": "text/plain"}
		payload = self.get_beneficiary_payload(action=payment_doc.action)

		encrypted_payload= self.aes_encrypt(
			payload, self.client_secret
		)

		response = requests.post(url, headers=headers, params=params, data=encrypted_payload)

		log_id= create_api_log(
			response,
			action="Update Beneficiary Details",
			account_config= payload,
			ref_doctype=self.doctype,
			ref_docname=self.name,
		)

		return self.get_decrypted_response(
			response, method="update_beneficiary_details", log_id=log_id
		)

	def update_client_credentials(self, action=None):
		if action:
			bcd = frappe.get_value(
				"Client Details",
				{
					"parent": self.name,
					"parentfield": "client_details",
					"parenttype": self.doctype,
					"action": action,
				},
			)
			if not bcd:
				frappe.throw(frappe._("Client Details not found"))

			bene_client = frappe.get_doc("Client Details", bcd)
			self.client_key = bene_client.get_password("client_key")
			self.client_secret = bene_client.get_password("client_secret")

		else:
			self.client_key = self.get_password("client_key")
			self.client_secret = self.get_password("client_secret")


	def get_oauth_token(self):
		params = {"grant_type": "client_credentials"}

		auth_string = f"{self.client_key}:{self.client_secret}"

		# Encode the credentials
		encoded_credential = "Basic " + base64.b64encode(auth_string.encode()).decode()

		headers = {
			"Content-Type": "application/x-www-form-urlencoded",
			"Authorization": encoded_credential,
		}

		response = requests.post(self.urls.oauth_token, params=params, headers=headers)

		create_api_log(response, action="Get OAuth Token")

		if response.ok:
			return response.json().get("access_token")
		else:
			frappe.throw("Error in getting OAuth Token. Please check your credentials.")

	def set_decrypted_response(self, log_id, response_data):
		if isinstance(response_data, dict):
			response_data = json.dumps(response_data, indent=4)

		if frappe.db.exists("Bank Request Log", log_id):
			frappe.db.set_value(
				"Bank Request Log", log_id, "decrypted_response", response_data
			)

	def get_decrypted_response(self, response, method, log_id=None):
		res_dict = frappe._dict({})

		if response.ok:
			decrypted_response = self.aes_decrypt(
				response.text, self.client_secret
			)
			self.set_decrypted_response(log_id, decrypted_response)

			if method in ["make_payment", "payment_status"]:
				self.get_formated_response(decrypted_response, res_dict, method)
			elif method == "bank_statement":
				self.get_formated_bank_statement_response(decrypted_response, res_dict)
			elif method == "update_beneficiary_details":
				self.get_formated_response_for_beneficiary(
					decrypted_response, res_dict, action=self.payment_doc.action
				)

		else:
			res_dict.status = "Request Failure"
			res_dict.error = response.text

		return res_dict

	def get_formated_bank_statement_response(self, data, res_dict):
		root = ET.fromstring(data)
		namespace = {"fixml": "http://www.finacle.com/fixml"}

		transactions = []
		for txn in root.findall(".//fixml:TransactionDetails", namespaces=namespace):
			transaction = {
				"transaction_date": txn.findtext(
					"fixml:TranDate", namespaces=namespace
				),
				"transaction_amount": txn.findtext(
					"fixml:TranAmt", namespaces=namespace
				),
				"reference_number": txn.findtext("fixml:RefNum", namespaces=namespace),
			}
			transactions.append(transaction)

		res_dict.server_status = "Success"
		res_dict.bank_statements = transactions

	def get_formated_response_for_beneficiary(self, data, res_dict, action=None):
		action_success_msg = {
			"Submit": "Beneficiary Submitted successfully",
			"Update": "Beneficiary Updated successfully",
			"Discard": "Beneficiary Discarded successfully",
			"Approve": "Beneficiary Approved successfully",
			"Reject": "Beneficiary Rejected successfully",
			"Suspend": "Beneficiary Suspended successfully",
		}
		if isinstance(data, str) and data.strip().startswith("{"):
			data = json.loads(data)
		else:
			res_dict.status = "failed"
			res_dict.error = data
			return res_dict

		bank_details = data.get("data", {})
		errors = data.get("errors", [])

		if action == "Submit":
			bank_account_details = bank_details.get("bankAccount", {})
			if bank_account_details and (association_id:=bank_account_details.get("associationId", "")):
				res_dict.status = "success"
				res_dict.association_id = association_id
				res_dict.message = "Beneficiary submitted successfully."
		elif action == "Update":
			if bank_details.get("Status") == "Success":
				res_dict.status = "success"
				res_dict.message = action_success_msg[action]

		elif action in ("Update", "Discard", "Approve", "Reject", "Suspend"):
			if bank_details.get("status", "") == "success":
				res_dict.status = "success"
				res_dict.message = action_success_msg[action]

		error_msg = ""
		if errors and res_dict.status != "success":
			for error in errors:
				error_msg +=(error.get("description", "") + "<br>")

			res_dict.status = "failed"
			res_dict.error = error_msg

	def get_formated_response(self, data, res_dict, method):
		root = ET.fromstring(data)

		if method == "make_payment":
			namespace = {
				"SOAP-ENV": "http://www.w3.org/2003/05/soap-envelope",
				"ns0": "http://www.kotak.com/schemas/CMS_Generic/Payment_Response.xsd",
			}

			status_code = cstr(root.find(".//ns0:StatusCd", namespaces=namespace).text)
			message = self.get_status_description(status_code)

			if status_code in ["000", "005"]:
				res_dict.status = "ACCEPTED"
			elif status_code in [
				"001",
				"002",
				"003",
				"004",
				"006",
				"008",
				"009",
				"010",
				"011",
			]:
				res_dict.status = "Failed"

			res_dict.message = message

		elif method == "payment_status":
			namespace = {
				"SOAP-ENV": "http://www.w3.org/2003/05/soap-envelope",
				"ns0": "http://www.kotak.com/schemas/CMS_Generic/Reversal_Response.xsd",
			}

			rev_details = root.findall(".//ns0:Rev_Detail", namespace)
			payment_status_details = frappe._dict()

			for detail in rev_details:
				msg_id = detail.find("ns0:Msg_Id", namespace).text
				status_code = detail.find("ns0:Status_Code", namespace).text
				status_desc = detail.find("ns0:Status_Desc", namespace).text

				if msg_id:
					msg, sts = self.get_status_description(status_code)
					if status_code == "R" and status_desc == "REJECTED":
						sts = "Failed"

					payment_status_details[msg_id] = {
						"status": sts,
						"message": msg,
						"utr_number": detail.find("ns0:UTR", namespace).text,
					}

			if self.bulk_transaction:
				res_dict.status = "Processed"
				res_dict.payment_status_details = payment_status_details
			else:
				return res_dict.update(
					payment_status_details.get(self.payment_doc.name, {})
				)


	def get_account_config(self, method):
		if method in ["make_payment", "payment_status"]:
			return self.get_xml_payload(method)
		elif method == "bank_statement":
			return self.get_statement_xml_payload()

	def get_statement_xml_payload(self):
		payload_details = self.doc

		def _dict_to_xml(data, root_tag="FIXML"):
			root = ET.Element(root_tag)

			def build_tree(element, data):
				"""Recursively build XML tree"""
				if isinstance(data, dict):
					for key, value in data.items():
						if key.startswith("@"):  # Handle attributes
							element.set(key[1:], value)
						else:
							sub_element = ET.SubElement(element, key)
							build_tree(sub_element, value)
				elif isinstance(data, list):
					for item in data:
						sub_element = ET.SubElement(element, "Item")
						build_tree(sub_element, item)
				else:
					element.text = str(data)

			build_tree(root, data)
			return ET.ElementTree(root)

		fixml_dict = {
			"@xmlns": "http://www.finacle.com/fixml",
			"Header": {
				"RequestHeader": {
					"MessageKey": {
						"RequestUUID": get_id(10),
						"ServiceRequestId": "executeFinacleScript",
						"ChannelId": "DAP",
					},
					"RequestMessageInfo": {
						"BankId": "01",
						"MessageDateTime": get_datetime().strftime(
							"%Y-%m-%dT%H:%M:%S.%f"
						)[:-3],
					},
				}
			},
			"Body": {
				"executeFinacleScriptRequest": {
					"ExecuteFinacleScriptInputVO": {
						"requestId": "intf_AcctTrnInq_main.scr"
					},
					"executeFinacleScript_CustomData": {
						"AcctTrnInqRq": {
							"Foracid": self.forac_id,
							"FromDate": getdate(payload_details.from_date).strftime("%d-%m-%Y"),
							"ToDate": getdate(payload_details.to_date).strftime("%d-%m-%Y"),
						}
					},
				}
			},
		}
		# Convert dictionary to XML
		tree = _dict_to_xml(fixml_dict)

		return ET.tostring(tree.getroot(), encoding="utf-8").decode()


	def get_beneficiary_payload(self, action=None):
		if action not in ('Submit', 'Update', 'Discard', 'Reject', 'Suspend', 'Approve'):
			frappe.throw(frappe._("Invalid Action"))

		payment_doc = self.payment_doc

		if action in ["Submit", "Update"]:
			data= {
				"clientId": self.client_id or self.client_code,
				"legalEntity":"IN",
				"beneficiaryId": payment_doc.name,
				"beneficiaryName":payment_doc.beneficiary_name,
				"beneficiaryType":payment_doc.beneficiary_type or "INDIVIDUAL",
				"leiCode":payment_doc.lei_code or "",
				"beneficiaryLimit":{
					"limitLevel": payment_doc.limit_level or "NONE",
					"limitFrequency":payment_doc.limit_frequency or "",
					"limitOnTransactions":payment_doc.limit_on_transactions or 0,
					"limitOnAmount":payment_doc.limit_on_amount or 0
				},
				"mobile":payment_doc.mobile,
				"email":payment_doc.email,
				"postalAddress":{
					"addressType":"ADDR",
					"addressLine1":"",
					"addressLine2":"",
					"addressLine3":""
				},
				"bankAccount":{
					"paymentType":payment_doc.payment_type,
					"packageType": self.package_type or "DEFAULT",
					"packageCode":self.package_code or "BBPACKAGE",
					"packageName":self.package_name or "BBPackage",
					"isDefaultAccount":"Y",
					"account":{
						"id":{
							"other":{
							"id": payment_doc.bank_account_no
							}
						},
						"type":"CURRENT",
						"currency":"INR"
					},
					"benificiaryBank":{
						"identifierType":"IFSC",
						"otherId":payment_doc.branch_code,
						"name": payment_doc.branch_name or ""
					}
				}
			}
			if action == "Submit":
				data["makerRemarks"] = "Add Bene"
			elif action in ["Discard", "Update"]:
				data["associationId"] = payment_doc.association_id
				data["makerRemarks"] = "Maker Beneficiary "+ action
				data.pop("beneficiaryId", None)

			return data

		elif action in ["Approve", "Reject", "Suspend"]:
			return {
				"event": cstr(action).upper(),
				"associationId":payment_doc.association_id,
				"checkerRemarks": "Checker Beneficiary "+action,
				"makerRemarks": "Maker Beneficiary "+action,
			}
		elif action == "Discard":
			return {
				"clientId": self.client_id or self.client_code,
				"beneficiaryId":payment_doc.name,
				"accountNumber": payment_doc.bank_account_n or "",
			}
		else:
			frappe.throw(frappe._("Invalid Beneficiary Action"))


	def get_xml_payload(self, method):
		def _dict_to_xml(tag, data, namespaces={}):
			"""Convert a dictionary to an XML element."""
			if namespaces:
				element = ET.Element(
					tag, {f"xmlns:{prefix}": uri for prefix, uri in namespaces.items()}
				)
			else:
				element = ET.Element(tag)

			for key, value in data.items():
				if isinstance(value, dict):
					child = _dict_to_xml(key, value)
					element.append(child)
				elif isinstance(value, list):
					for val in value:
						if isinstance(val, dict):
							child = _dict_to_xml(key, val)
							element.append(child)
						elif isinstance(val, str):
							child = ET.SubElement(element, key)
							child.text = cstr(val)
				else:
					child = ET.SubElement(element, key)
					child.text = cstr(value)

			return element

		json_data = self.get_formated_payload_json(method=method)

		namespaces = {
			"make_payment": {
				"soap": "http://www.w3.org/2003/05/soap-envelope",
				"pay": "http://www.kotak.com/schemas/CMS_Generic/Payment_Request.xsd",
			},
			"payment_status": {
				"soap": "http://www.w3.org/2003/05/soap-envelope",
				"rev": "http://www.kotak.com/schemas/CMS_Generic/Reversal_Request.xsd",
			},
		}.get(method, {})

		# Build XML
		root = _dict_to_xml("soap:Envelope", json_data, namespaces)

		return ET.tostring(root, encoding="utf-8", short_empty_elements=False).decode(
			"utf-8"
		)

	def get_formated_payload_json(self, method):
		conector_doc = self
		payment = self.payment_doc if not self.bulk_transaction else self.doc

		if method == "make_payment":
			return {
				"soap:Header": {},
				"soap:Body": {
					"pay:Payment": {
						"pay:RequestHeader": {
							"pay:MessageId": get_id(len(payment.name), payment.name),
							"pay:MsgSource": conector_doc.client_code,
							"pay:ClientCode": conector_doc.client_code,
							"pay:BatchRefNmbr": get_id(len(payment.name), payment.name),
						},
						"pay:InstrumentList": list(self.get_instrument_list(payment))
						if self.bulk_transaction
						else self.get_instrument(payment),
					}
				},
			}

		elif method == "payment_status":
			payment_date, msg_ids = self.get_payment_id_and_date(payment)

			return {
				"soap:Header": {},
				"soap:Body": {
					"rev:Reversal": {
						"rev:Header": {
							"rev:Req_Id": get_id(15),
							"rev:Msg_Src": conector_doc.prod_code,
							"rev:Client_Code": conector_doc.client_code,
							"rev:Date_Post": payment_date,
						},
						"rev:Details": {"rev:Msg_Id": msg_ids},
					}
				},
			}

	def get_payment_id_and_date(self, payment):
		payment_date = None
		ids = []
		if not self.bulk_transaction:
			return payment.payment_date, [get_id(len(payment.name), payment.name)]
		else:
			for payment_details in payment.get("summary", []):
				payment_details = frappe._dict(payment_details)
				if payment_details.payment_date:
					payment_date = payment_details.payment_date
					ids.append(get_id(len(payment_details.name), payment_details.name))

		return payment_date, ids

	def get_mode_of_transfer(self, mode_of_transfer):
		if "A2A" in mode_of_transfer:
			mode_of_transfer = "IFT"

		return mode_of_transfer

	def get_instrument(self, payment_details):
		connector = self
		return {
			"pay:instrument": {
				"pay:InstRefNo": get_id(
					len(payment_details.name), payment_details.name
				),
				"pay:CompanyId": connector.client_code,
				"pay:CompBatchId": "",
				"pay:ConfidentialInd": "N",
				"pay:MyProdCode": connector.prod_code,
				"pay:PayMode": self.get_mode_of_transfer(
					payment_details.mode_of_transfer
				),
				"pay:TxnAmnt": payment_details.amount,
				"pay:AccountNo": connector.account_number,
				"pay:DrRefNmbr": "Pay",
				"pay:DrDesc": f"Payment from {payment_details.parent}",
				"pay:PaymentDt": getdate().strftime("%Y-%m-%d"),
				"pay:BankCdInd": "M",
				"pay:RecBrCd": payment_details.branch_code,
				"pay:BeneAcctNo": payment_details.bank_account_no,
				"pay:BeneName": payment_details.beneficiary_name,
				"pay:BeneCode": payment_details.beneficiary,
				"pay:BeneEmail": payment_details.email or "",
				"pay:BeneMb": payment_details.mobile or "",
				"pay:BeneAddr1": "",
				"pay:BeneAddr2": "",
				"pay:BeneAddr3": "",
				"pay:BeneAddr4": "",
				"pay:BeneAddr5": "",
				"pay:city": "",
				"pay:zip": "",
				"pay:Country": "INDIA",
				"pay:State": "",
				"pay:TelephoneNo": "",
				"pay:PaymentRef": "",
				"pay:ChgBorneBy": "",
				"pay:CreditRefNo": "",
				"pay:PaymentDtl": "",
				"pay:PaymentDtl1": "",
				"pay:PaymentDtl2": "",
				"pay:PaymentDtl3": "",
				"pay:EnrichmentSet": {"pay:Enrichment": payment_details.desc},
			}
		}

	def get_instrument_list(self, payments):
		if not payments.get("summary"):
			return []

		for payment_details in payments.get("summary", []):
			yield self.get_instrument(frappe._dict(payment_details))

	def get_transaction_history(self):
		return "Transaction History Not Implemented"

	def get_balance(self):
		return "Balance Not Implemented"

	def get_status_description(self, status_code):
		return {
			"000": "All Instruments accepted Successfully.",
			"001": "XML Schema validation failed",
			"002": "Duplicate Message Id",
			"003": "Invalid Client Code.",
			"004": "Duplicate Instrument Ref Number within Request.",
			"005": "Request Partially Accepted.",
			"006": "Instrument rejected due to data validation failure.",
			"007": "Instrument validated successfully.",
			"008": "Invalid Web service consumer IP address.",
			"009": "All Instruments rejected due to data validation failure",
			"010": "Default user not found for given client.",
			"011": "System encountered severe error. Please contact admin.",
			"C": ("In Process", "Pending"),
			"U": ("Processed", "Processed"),
			"AR": ("Rejected", "Rejected"),
			"CR": ("Pending Repair", "Rejected"),
			"CF": ("Returned", "Rejected"),
			"PA": ("Pending Approval", "Pending"),
			"PS": ("Pending Send", "Pending"),
			"DL": ("Deleted", "Rejected"),
			"DF": ("Debit Failed", "Failed"),
			"DC": ("Debited", "Pending"),
			"CN": ("Cancelled", "Failed"),
			"O": ("Draft", "Pending"),
			"R": ("Rejected", "Failure"),
		}.get(cstr(status_code), (f"{status_code} Description Not Available", ""))
