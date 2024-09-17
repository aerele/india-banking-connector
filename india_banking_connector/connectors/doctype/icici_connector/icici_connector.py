# Copyright (c) 2024, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

import frappe
import json
from frappe.model.document import Document
from india_banking_connector.connectors.bank_connector import BankConnector
import india_banking_connector.utils as utils
from india_banking_connector.india_banking_connector.doctype.bank_request_log.bank_request_log import create_api_log

class ICICIConnector(BankConnector):
	bank = "ICICI Bank"
	BLOCK_SIZE = 16

	def __init__(self, *args, **kwargs):
		kwargs.update(bank = self.bank, BLOCK_SIZE = self.BLOCK_SIZE)
		super().__init__(*args, **kwargs)

		self.bulk_transaction = kwargs.get('bulk_transaction')
		self.payment_doc = frappe._dict(kwargs.get('payment_doc', {}))

	def intiate_payment(self):
		account_config = {
			"FILE_DESCRIPTION": payment_doc.file_reference_id,
			"CORP_ID": connector_doc.corp_id,
			"USER_ID": connector_doc.payment_creator_user_id,
			"AGGR_ID": connector_doc.aggr_id,
			"AGGR_NAME": connector_doc.aggr_name,
			"URN": connector_doc.urn,
			"UNIQUE_ID": payment_doc.unique_id,
			"AGOTP": str(payload.otp),
			"FILE_NAME":f"{payment_doc.file_reference_id}.txt",
			"FILE_CONTENT": utils.construct_payment_details_content(payment_doc,connector_doc)
		}

		res_dict = frappe._dict({})

		basic_defaults = self.get_basic_defaults()

		encrypted_data = self.encrypt_data(
			data = json.dumps(account_config).encode("UTF-8"),
			key =  basic_defaults.aes_key,
			IV = basic_defaults.iv,
			BLOCK_SIZE = basic_defaults.block_size
		)

		encrypted_key = self.encrypt_key(basic_defaults.aes_key, self.get_file_relative_path(self.bank_public_key))

		payload = self.get_payload(encrypted_key, encrypted_data)

		response = requests.post(self.urls.make_payment, headers=self.headers, data=json.dumps(payload))

		create_api_log(response, action=  "Initiate Payment", account_config = account_config, ref_doctype= payment_doc.doctype, ref_docname= payment_doc.name)

		if response.ok:
			decrypted_key = decrypt_key(response.get("encryptedKey"), self.get_file_relative_path(self.private_key))
			decrypted_response = self.decrypt_data(response.get('encryptedData'), decrypted_key.encode("utf-8"))

			res_dict.res_text = decrypted_response
			res_dict.res_status = response.status_code
			res_dict.api_method = "make_payment"
			res_dict.config_details = account_config
			res_dict.payload = payload

			if decrypted_response.get('FILE_SEQUENCE_NUM'):
				res_dict.server_status = "success"
				res_dict.server_message = decrypted_response.get('MESSAGE_DESC')
				res_dict.file_sequence_number = decrypted_response.get('FILE_SEQUENCE_NUM')

			elif decrypted_response.get('errormessage') or decrypted_response.get('ErrorCode'):
				res_dict.server_status="failed"
				err_msg=None
				if decrypted_response.get('ErrorCode'):
					err_msg = utils.get_error_message(decrypted_response.get('ErrorCode'))

				res_dict.server_message = err_msg or decrypted_response.get('errormessage') or decrypted_response.get('Message')
		else:
			res_dict.res_text = response.text
			res_dict.res_status = response.status_code
			res_dict.api_method = "make_payment"
			res_dict.config_details = account_config
			res_dict.payload = payload
			res_dict.server_status="failed"

	def get_payment_status(self):
		account_config = {
			"CORPID": connector_doc.corp_id,
			"USERID": connector_doc.payment_status_checker_user_id or connector_doc.payment_creator_user_id,
			"AGGRID": connector_doc.aggr_id,
			"URN":connector_doc.urn,
			"FILESEQNUM": payment_doc.file_sequence_number,
			"ISENCRYPTED":"N"
		}

		basic_defaults = self.get_basic_defaults()

		encrypted_data = utils.encrypt_data(
			data = json.dumps(account_config).encode("UTF-8"),
			key = basic_defaults.aes_key,
			IV = basic_defaults.iv,
			BLOCK_SIZE = basic_defaults.block_size
		)

		encrypted_key = self.encrypt_key(basic_defaults.aes_key, self.get_file_relative_path(self.bank_public_key))

		payload = self.get_payload(encrypted_key, encrypted_data)

		response = requests.post(self.urls.get_payment_status, headers=self.headers, data=json.dumps(payload))

		create_api_log(response, action=  "Initiate Payment", account_config = account_config, ref_doctype= payment_doc.doctype, ref_docname= payment_doc.name)

		res_dict = frappe._dict({})

		if response.ok:
			decrypted_key = self.decrypt_key(response.get("encryptedKey"), self.get_file_relative_path(self.private_key))
			decrypted_response = self.decrypt_data(response.get('encryptedData'), decrypted_key.encode("utf-8"))

			res_dict.res_text = decrypted_response
			res_dict.res_status = response.status_code
			res_dict.api_method = "get_payment_status"
			res_dict.config_details = account_config
			res_dict.payload = payload

			if decrypted_response.get('XML',{}).get('FILE_STATUS'):
				res_dict.server_status = "success"
				res_dict.file_status = decrypted_response.get('XML').get('FILE_STATUS')
				res_dict.server_message = utils.get_file_status(decrypted_response.get('XML').get('FILE_STATUS'))
				res_dict.payment_status = {}

				if decrypted_response.get('XML').get('FILEUPLOAD_BINARY_OUTPUT').get('Records').get('Record'):
					res_dict.payment_status = utils.format_payment_status(
						decrypted_response.get('XML').get('FILEUPLOAD_BINARY_OUTPUT').get('Records').get('Record')
					)
			
			elif decrypted_response.get('errormessage') or decrypted_response.get('ErrorCode'):
				res_dict.server_status="failed"
				err_msg=None
				if decrypted_response.get('ErrorCode'):
					err_msg = utils.get_error_message(decrypted_response.get('ErrorCode'))
				res_dict.server_message=err_msg or decrypted_response.get('errormessage') or decrypted_response.get('Message')
		else:
			res_dict.res_text = response.text
			res_dict.res_status = response.status_code
			res_dict.api_method = "get_payment_status"
			res_dict.config_details = account_config
			res_dict.payload = payload
			res_dict.server_status="failed"

	def get_transaction_history(self):
		return "Transaction History Not Implemented"

	def get_balance(self):
		return "Balance Not Implemented"

	def get_oauth_token(self):
		return "OAuth Token Not Implemented"

	def generate_otp(self):
		account_config = {
			'CORPID': self.corp_id,
			'USERID': self.payment_creator_user_id,
			'AGGRID': self.aggr_id,
			'AGGRNAME': self.aggr_name,
			'URN': self.urn,
			'UNIQUEID': self.payment_doc.unique_id,
			'AMOUNT': str(self.payment_doc.total)
		}

		basic_defaults = self.get_basic_defaults()

		encrypted_data = self.encrypt_data(
			data = json.dumps(account_config).encode("UTF-8"),
			key = basic_defaults.aes_key,
			IV = basic_defaults.iv,
			BLOCK_SIZE = basic_defaults.block_size
		)

		encrypted_key = self.encrypt_key(basic_defaults.aes_key, self.get_file_relative_path(self.bank_public_key))

		payload = self.get_payload(encrypted_key, encrypted_data)

		response = requests.post(self.urls.generate_otp, headers=self.headers, data=json.dumps(payload))

		create_api_log(response, action=  "Initiate Payment", account_config = account_config, ref_doctype= payment_doc.doctype, ref_docname= payment_doc.name)

		res_dict = frappe._dict({})

		if response.ok:
			decrypted_key = decrypt_key(response.get("encryptedKey"), self.get_file_relative_path(self.private_key))
			decrypted_response = self.decrypt_data(response.get('encryptedData'), decrypted_key.encode("utf-8"))

			res_dict.res_text = decrypted_response
			res_dict.res_status = response.status_code
			res_dict.api_method = "generate_otp"
			res_dict.config_details = account_config
			res_dict.payload = payload

			if decrypted_response.get('RESPONSE') and decrypted_response.get('RESPONSE') == "Success":
				res_dict.server_status="success"
				res_dict.server_message= decrypted_response.get('MESSAGE')

			elif decrypted_response.get('errormessage'):
				res_dict.server_status="failed"
				err_msg=None
				if decrypted_response.get('ErrorCode'):
					err_msg = utils.get_error_message(decrypted_response.get('ErrorCode'))

				res_dict.server_message=err_msg or decrypted_response.get('errormessage') or decrypted_response.get('Message')
		else:
			res_dict.res_text = response.text
			res_dict.res_status = response.status_code
			res_dict.api_method = "generate_otp"
			res_dict.config_details = account_config
			res_dict.payload = payload
			res_dict.server_status="failed"
	