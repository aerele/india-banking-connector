# Copyright (c) 2024, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

import frappe, requests, json
from frappe.utils import getdate, cstr
from india_banking_connector.connectors.bank_connector import BankConnector
import india_banking_connector.utils as utils
from india_banking_connector.india_banking_connector.doctype.bank_request_log.bank_request_log import create_api_log
import base64

from india_banking_connector.utils import get_id

from xmltodict import parse as xml_to_dict
import xml.etree.ElementTree as ET

class KotakMahindraConnector(BankConnector):
	bank = "Kotak Mahindra Bank"
	IV = "0000000000000000".encode("utf-8")

	__all__ = ['intiate_payment', 'get_payment_status']

	def __init__(self, *args, **kwargs):
		kwargs.update(bank = self.bank)

		kwargs.update(iv = self.IV)

		super().__init__(*args, **kwargs)

		self.bulk_transaction = kwargs.get('bulk_transaction')
		self.doc = frappe._dict(kwargs.get('doc', {}))
		self.payment_doc = frappe._dict(kwargs.get('payment_doc', {}))

	def is_active(self):
		if not self.active:
			frappe.throw("Connector not active. Please contact admin.")

	@property
	def urls(self):
		if self.testing:
			return frappe._dict({
				"oauth_token": "https://apigwuat.kotak.com:8443/auth/oauth/v2/token",
				"make_payment" : "https://apigwuat.kotak.com:8443/v1/cms/pay",
				"payment_status" : "https://apigwuat.kotak.com:8443/v1/cms/rev",
				"generate_otp" : "",
				"bank_balance": "",
				"bank_statement": "",
				"bank_statement_paginated": ""
			})
		else:
			return frappe._dict({
				"oauth_token": "https://apigw.kotak.com:8443/auth/oauth/v2/token",
				"make_payment" : "https://apigw.kotak.com:8443/v1/cms/pay",
				"payment_status" : "https://apigw.kotak.com:8443/v1/cms/rev",
				"generate_otp" : "",
				"bank_balance": "",
				"bank_statement": "",
				"bank_statement_paginated": ""
				})

	@property
	def headers(self):
		return {
			"Content-Type": "application/xml",
			"Authorization": "Bearer "+ self.get_oauth_token()
		}

	def intiate_payment(self):
		url = self.urls.make_payment
		headers = self.headers
		payload = self.get_encrypted_payload(method= 'make_payment')

		response = requests.post(url, headers=headers, data= payload)

		# response = frappe._dict()
		# response.text = ""

		log_id = create_api_log(
			response, action= "Initiate Payment",
	  		account_config = self.get_account_config("make_payment"),
			ref_doctype= self.payment_doc.parenttype,
			ref_docname= self.payment_doc.parent
		)

		return self.get_decrypted_response(response, method= "make_payment", log_id=log_id)

	def get_payment_status(self):
		url = self.urls.payment_status
		headers = self.headers
		payload = self.get_encrypted_payload(method= 'payment_status')

		response = requests.post(url, headers=headers, data= payload)

		# response = frappe._dict()
		# response.text = ""
		
		log_id = create_api_log(
			response, action= "Payment Status",
	  		account_config = self.get_account_config("payment_status"),
			ref_doctype= self.payment_doc.parenttype,
			ref_docname= self.payment_doc.parent
		)

		return self.get_decrypted_response(response, method= "payment_status", log_id=log_id)

	def get_oauth_token(self):
		params = {
			"grant_type": "client_credentials"
		}

		auth_string = self.get_password('client_key') + ":" + self.get_password('client_secret')

		encoded_credintial = "Basic "+ base64.b64encode(auth_string.encode()).decode()

		headers = {
			'Content-Type': 'application/x-www-form-urlencoded',
			'Authorization': encoded_credintial
		}

		response = requests.post(self.urls.oauth_token, params= params, headers= headers)

		create_api_log(response, action=  "Get OAuth Token")

		if response.ok:
			return response.json().get('access_token')
		else:
			frappe.throw('Error in getting OAuth Token. Please check your credentials.')

	def set_decrypted_response(self, log_id, response_data):
		response_data = response_data

		if frappe.db.exists("Bank Request Log", log_id):
			frappe.db.set_value("Bank Request Log", log_id,"decrypted_response" , response_data)

	def get_decrypted_response(self, response, method, log_id= None):
		res_dict = frappe._dict({})
		if response.ok:
			if method == "make_payment":
				decrypted_response = self.aes_decrypt(response.text, self.get_password('client_secret').encode("utf-8"))
				self.set_decrypted_response(log_id, decrypted_response)

				return self.get_formated_response(decrypted_response, method)

			elif method == "payment_status":
				decrypted_response = self.aes_decrypt(response.text, self.get_password('client_secret').encode("utf-8"))
				self.set_decrypted_response(log_id, decrypted_response)

				return self.get_formated_response(decrypted_response, method)
		else:
			res_dict.status = 'Request Failure'
			res_dict.error = response.text

		return res_dict

	def get_formated_response(self, data, method):
		if self.bulk_transaction:
			payment = self.doc
		else:
			payment = self.payment_doc

		res_dict = frappe._dict({})

		if method == "make_payment":
			root = ET.fromstring(data)

			namespace = {
    			'SOAP-ENV': 'http://www.w3.org/2003/05/soap-envelope',
                'ns0': 'http://www.kotak.com/schemas/CMS_Generic/Payment_Response.xsd'
            }
   
			status_code = root.find('.//ns0:StatusCd', namespaces=namespace).text

			message = self.get_status_description(status_code)

			if status_code and cstr(status_code) in ["000", "005"]:
				res_dict.status = 'ACCEPTED'
			elif status_code and cstr(status_code) in ["001", "002", "003", "004", "006", "008", "009", "010", "011"]:
				res_dict.status = 'Failed'

			res_dict.message = message
		
		elif method == "payment_status":
			root = ET.fromstring(data)

			namespace = {
				'SOAP-ENV': 'http://www.w3.org/2003/05/soap-envelope',
				'ns0': 'http://www.kotak.com/schemas/CMS_Generic/Reversal_Response.xsd',
			}

			rev_details = root.findall('.//ns0:Rev_Detail', namespace)

			payment_status_details = frappe._dict()

			for detail in rev_details:
				msg_id = detail.find('ns0:Msg_Id', namespace).text
				status_code = detail.find('ns0:Status_Code', namespace).text
				status_desc = detail.find('ns0:Status_Desc', namespace).text
				utr = detail.find('ns0:UTR', namespace).text
				if msg_id:
					msg, sts = self.get_status_description(detail.find('ns0:Status_Code', namespace).text)
					payment_status_details.update({
						msg_id: {
							"status":msg,
							"message": sts,
							"utr_number":detail.find('ns0:UTR', namespace).text
						}
					})

			if self.bulk_transaction:
				res_dict.status = 'Processed'
				res_dict.payment_status_details = payment_status_details
			else:
				return payment_status_details.get(payment.name)

		return res_dict

	def get_encrypted_payload(self, method):
		return self.aes_encrypt(self.get_account_config(method), self.get_password('client_secret'))

	def get_account_config(self, method):
		if method == 'make_payment':
			return self.get_xml_payload(method= "make_payment")

		elif method == "payment_status":
			return self.get_xml_payload(method= "payment_status")

	def get_xml_payload(self, method):
		
		def dict_to_xml(tag, data, namespaces= {}):
			"""Convert a dictionary to an XML element."""
			if namespaces:
				element = ET.Element(tag, {f"xmlns:{prefix}": uri for prefix, uri in namespaces.items()})
			else:
				element = ET.Element(tag)

			for key, value in data.items():
				if isinstance(value, dict):
					child = dict_to_xml(key, value)
					element.append(child)
				elif isinstance(value, list):
					for val in value:
						child = ET.SubElement(element, key)
						child.text = cstr(val)
				else:
					child = ET.SubElement(element, key)
					child.text = cstr(value)

			return element

		json_data = self.get_formated_payload_json(method= method)

		# Build XML
		if method == "make_payment":
			namespaces = {
				"soap": "http://www.w3.org/2003/05/soap-envelope",
				"pay": "http://www.kotak.com/schemas/CMS_Generic/Payment_Request.xsd"
			}

			root = dict_to_xml("soap:Envelope", json_data, namespaces)

			return ET.tostring(root, encoding= "utf-8", short_empty_elements=False).decode('utf-8')

		elif method == "payment_status":
			namespaces = {
				"soap": "http://www.w3.org/2003/05/soap-envelope",
				"rev": "http://www.kotak.com/schemas/CMS_Generic/Reversal_Request.xsd"
			}
			root = dict_to_xml("soap:Envelope", json_data, namespaces)

			return ET.tostring(root, encoding= "utf-8")

	def get_formated_payload_json(self, method):
		conector_doc = self
		if self.bulk_transaction:
			payment = self.doc
		else:
			payment = self.payment_doc

		if method == "make_payment":
			return {
			"soap:Header": {},
			"soap:Body": {
				"pay:Payment": {
					"pay:RequestHeader": {
						"pay:MessageId": get_id(len(payment.name), payment.name),
						"pay:MsgSource": conector_doc.client_code,
						"pay:ClientCode": conector_doc.client_code,
						"pay:BatchRefNmbr": get_id(len(payment.name), payment.name)
					},
					"pay:InstrumentList": list(self.get_instrument_list(payment)) if self.bulk_transaction else self.get_instrument(payment)
				}}
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
							"rev:Date_Post":  payment_date,
						},
						"rev:Details": {
							"rev:Msg_Id": msg_ids
						}
					}
				}
    		}
	def get_payment_id_and_date(self, payment):
		payment_date = None
		ids = []
		if not self.bulk_transaction:
			return payment.payment_date, [get_id(len(payment.name), payment.name)]
		else:
			for payment_details in payment:
				payment_details = frappe._dict(payment_details)
				if payment_details.payment_date:
					payment_date = payment_details.payment_date
					ids.append(get_id(len(payment_details.name), payment_details.name))

		return payment_date, ids

	def get_mode_of_payment(self, mode_of_transfer):
		if 'A2A' in mode_of_transfer:
			mode_of_transfer = "IFT"

		return mode_of_transfer

	def get_instrument(self, payment_details):
		connector = self
		return {
			"pay:instrument": {
				"pay:InstRefNo": get_id(len(payment_details.name), payment_details.name),
				"pay:CompanyId": connector.client_code,
				"pay:MyProdCode": connector.prod_code,
				"pay:PayMode": self.get_mode_of_payment(payment_details.mode_of_transfer),
				"pay:TxnAmnt": payment_details.amount,
				"pay:AccountNo": connector.account_number,
				"pay:DrDesc": payment_details.desc,
				"pay:PaymentDt": getdate().strftime("%Y-%m-%d"),
				"pay:RecBrCd": payment_details.branch_code,
				"pay:BeneAcctNo": payment_details.bank_account_no,
				"pay:BeneName": payment_details.party_name,
				"pay:BeneCode": payment_details.party,
				"pay:BeneEmail": payment_details.email,
				"pay:EnrichmentSet": {
					"pay:Enrichment": payment_details.desc
				}
			}
		}

	def get_instrument_list(self, payments):
		if not payments.get('summary'):
			return []

		for payment_details in payments:
			yield self.get_instrument(payment_details)

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
			"AR": ("Rejected", 'Rejected'),
			"CR": ("Pending Repair", "Rejected"),
			"CF": ("Returned", "Rejected"),
			"PA": ("Pending Approval", "Pending"),
			"PS": ("Pending Send", "Pending"),
			"DL": ("Deleted", "Rejected"),
			"DF": ("Debit Failed", "Failed"),
			"DC": ("Debited", "Pending"),
			"CN": ("Cancelled", "Failed"),
			"O": ("Draft", "Pending"),
			"R": ("Rejected", "Failed")
		}.get(cstr(status_code), (f"{status_code} Description Not Available", ""))
