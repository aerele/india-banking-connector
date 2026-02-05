# Copyright (c) 2026, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

import json
import os
import stat
from xml.dom.minidom import parseString
from xml.etree import ElementTree as ET
from xml.etree.ElementTree import tostring

import frappe
import gnupg
from frappe.core.api.file import create_new_folder
from frappe.utils import cint, cstr, flt, get_datetime, getdate
from frappe.utils.file_manager import get_file_path

from india_banking_connector.host_to_host.doctype.base_host import BaseHost
from india_banking_connector.host_to_host.doctype.citi_h2h_connector.citi_sftp_client import (
	CitiSFTPClient,
)
from india_banking_connector.utils import get_id


class CITIH2HConnector(BaseHost):
	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.doc = frappe._dict(kwargs.get("doc", {}))
		self.summary_details = {}
		self.to_be_generate_mot = []

	@frappe.whitelist()
	def get_files_list(self, folder=None):
		if not folder:
			folder = "."
		client = self.get_sftp_client()
		folders = client.list_files(folder)

		return "<br/>".join(folders) or "Files Not Found!"

	def make_payment_log(self, mot, file_content, payment_log_id):
		if not file_content:
			return

		filename = (
			"CITI_IN_Pay_"
			+ getdate().strftime("%d%m%Y")
			+ "_"
			+ payment_log_id
			+ "_"
			+ mot
			+ ".xml"
		)
		create_new_folder("Payment Log", "Home")
		file = frappe.new_doc("File")
		file.file_name = filename
		file.content = file_content
		file.folder = "Home/Payment Log"
		file.attached_to_doctype = "Payment Log"
		file.attached_to_name = payment_log_id
		file.attached_to_field = f"{mot}_payment_file"
		file.insert()

		frappe.db.set_value(
			"H2H Payment Log", payment_log_id, f"{mot}_payment_file", file.file_url
		)

		return file.file_url

	def make_payment_file(self, payment_log_id):
		payment_log_doc = frappe.get_doc("H2H Payment Log", payment_log_id)
		self.update_summary_details()

		requested_data = {}
		file_urls = {}

		for mot in self.to_be_generate_mot:
			if payment_log_doc.get(mot + "_payment_file"):
				continue

			xml_dict = self.build_xml_dict(mot)
			root_tag = list(xml_dict.keys())[0]
			root_value = xml_dict[root_tag]
			root = self.build_element(root_tag, root_value)

			xml_str = tostring(root, encoding="utf-8")
			file_content = parseString(xml_str).toprettyxml(indent="    ")

			file_url = self.make_payment_log(mot, file_content, payment_log_id)
			requested_data[mot] = file_content
			file_urls[f"{mot}_payment_file"] = file_url

		values = file_urls
		values["request"] = json.dumps(requested_data)
		frappe.db.set_value("H2H Payment Log", payment_log_id, values)

	def get_mode_of_transfer(self, mot):
		if mot in ["rtgs", "a2a"]:
			return "URGP"
		elif mot == "imps":
			return "IMPS"
		else:
			return "URNS"

	def get_transactions(self, summary_details):
		transactions = {}
		for summary in summary_details:
			# Round Bank rounding decimal 2 (eg. .989 to .99)
			amount = cstr(flt(summary.get("amount", 0.0), 2))
			remarks = (
				summary.get("remarks") or "Payment from " + summary.get("parent") or ""
			)
			tx_dict = {
				f"CdtTrfTxInf-{summary.name}": {
					"PmtId": {
						"InstrId": cstr(summary.name).upper(),
						"EndToEndId": cstr(summary.name).upper(),
					},
					"Amt": {"InstdAmt": {"@Ccy": "INR", "#text": amount}},
					"CdtrAgt": {
						"FinInstnId": {
							"ClrSysMmbId": {
								"MmbId": summary.branch_code,
							},
						}
					},
					"Cdtr": {
						"Nm": summary.party_name or summary.party,
						"PstlAdr": {"AdrLine": "INDIA", "AdrLine": "INDIA"},  # noqa: F601
					},
					"CdtrAcct": {
						"Id": {
							"Othr": {
								"Id": summary.bank_account_no,
							}
						},
						"Tp": {"Cd": "CACC"},
					},
					"Purp": {
						"Cd": "SUPP",
					},
					"RmtInf": {
						"Ustrd": remarks,
					},
				}
			}
			transactions.update(tx_dict)

		return transactions

	def build_xml_dict(self, mot):
		payment_details = frappe._dict(self.doc)

		unique_id = get_id(payment_details.name)

		company_address = {}
		if payment_details.company_address:
			company_address = json.loads(payment_details.company_address)
		address = frappe._dict(company_address)

		payment_dict = frappe._dict(
			{
				"unique_id": f"{unique_id}_{mot}",
				"company_name": payment_details.company,
				"summary_details": self.summary_details[mot]["summary"],
				# Bank rounding decimal 2 (eg. .989 to .99)
				"total": flt(self.summary_details[mot]["total"], 2),
				"street_name": ", ".join(address.get("AddressLine", [])),
				"building_no": address.get("AddressLine", [1])[0],
				"post_code": address.get("PostCode"),
				"town_name": address.get("TownName"),
				"country": address.get("Country", "").upper(),
			}
		)

		return self.map_dict_to_xml(payment_dict, mot)

	def map_dict_to_xml(self, payment_dict, mot):
		return {
			"Document": {
				"@xmlns": "urn:iso:std:iso:20022:tech:xsd:pain.001.001.03",
				"@xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
				"CstmrCdtTrfInitn": {
					"GrpHdr": {
						"MsgId": cstr(payment_dict.unique_id).upper(),
						"CreDtTm": get_datetime().strftime("%Y-%m-%dT%H:%M:%S"),
						"NbOfTxs": cstr(len(payment_dict.summary_details)),
						"CtrlSum": payment_dict.total,
						"InitgPty": {
							"Nm": payment_dict.company_name,
						},
					},
					"PmtInf": {
						"PmtInfId": cstr(payment_dict.unique_id).upper(),
						"PmtMtd": "TRF",  # Credit Transfer
						"BtchBookg": "false",
						"NbOfTxs": cstr(len(payment_dict.summary_details)),
						"CtrlSum": payment_dict.total,
						"PmtTpInf": {
							"InstrPrty": "NORM",
							**(
								{
									"SvcLvl": {
										"Cd": self.get_mode_of_transfer(mot),
									},
								}
								if mot == "neft"
								else {}
							),
							"LclInstrm": {
								"Prtry": "191907",
							},
							**(
								{
									"CtgyPurp": {
										"Cd": "SUPP",
									}
								}
								if mot == "neft"
								else {}
							),
						},
						"ReqdExctnDt": get_datetime().strftime("%Y-%m-%d"),
						"Dbtr": {
							"Nm": payment_dict.company_name,
						},
						"DbtrAcct": {
							"Id": {
								"Othr": {
									"Id": self.account_number,
								}
							},
						},
						"DbtrAgt": {
							"FinInstnId": {
								"BIC": getattr(self, "ifsc_code", "CITIINBXIBD"),
							}
						},
						"ChrgBr": "DEBT",
						# Transactions
						**self.get_transactions(
							summary_details=payment_dict.summary_details
						),
					},
				},
			}
		}

	def encrypt_payment_files(self, log_id):
		payment_log_doc = frappe.get_doc("H2H Payment Log", log_id)
		payment_files = (
			(
				"a2a",
				payment_log_doc.a2a_payment_file,
				payment_log_doc.a2a_encrypted_payment_file,
			),
			(
				"neft",
				payment_log_doc.neft_payment_file,
				payment_log_doc.neft_encrypted_payment_file,
			),
			(
				"rtgs",
				payment_log_doc.rtgs_payment_file,
				payment_log_doc.rtgs_encrypted_payment_file,
			),
			(
				"imps",
				payment_log_doc.imps_payment_file,
				payment_log_doc.imps_encrypted_payment_file,
			),
		)

		to_be_enc_mot = [
			(mot, file_url)
			for mot, file_url, encrypted_file_url in payment_files
			if file_url and not encrypted_file_url
		]

		gpg = self.init_gpg()

		recipient_fingerprint = self.citi_fingerprint
		signer_fingerprint = self.client_fingerprint

		encrypted_file_urls = {}
		for mot, payment_file in to_be_enc_mot:
			payment_file_path = get_file_path(payment_file)

			with open(payment_file_path, "rb") as f:
				encrypted = gpg.encrypt_file(
					f,
					recipients=[recipient_fingerprint],
					sign=signer_fingerprint,
					always_trust=True,
					passphrase=self.get_password("pgp_private_key_password")
					if self.pgp_private_key_password
					else None,
				)

				if encrypted.ok:
					file_name = frappe.get_value(
						"File", {"file_url": payment_file}, "file_name"
					)
					create_new_folder("Encrypted", "Home/Payment Log")

					file = frappe.new_doc("File")
					file.content = encrypted.data
					file.file_name = file_name + ".pgp"
					file.folder = "Home/Payment Log/Encrypted"
					file.attached_to_doctype = "Payment Log"
					file.attached_to_name = log_id
					file.is_private = 1
					file.attached_to_field = f"{mot}_encrypted_payment_file"
					file.file_type = "pgp"
					file.insert()

					encrypted_file_urls[f"{mot}_encrypted_payment_file"] = file.file_url
				else:
					frappe.log_error(f"Encryption failed-> {mot}", encrypted.stderr)
					frappe.throw(
						"Encryption failed please check the logs for more details"
					)

		if encrypted_file_urls:
			frappe.db.set_value("H2H Payment Log", log_id, encrypted_file_urls)
			return True

		return False

	def init_gpg(self):
		gpg_home = "/tmp/.gnupg_citi_h2h/"
		os.makedirs(gpg_home, exist_ok=True)
		os.chmod(gpg_home, stat.S_IRWXU)
		gpg = gnupg.GPG(gnupghome=gpg_home)

		# Import Client Private key
		with open(get_file_path(self.pgp_private_key), "rb") as f:
			gpg.import_keys(f.read())

		# Import Client Public Key
		with open(get_file_path(self.pgp_public_key), "rb") as f:
			gpg.import_keys(f.read())

		# Import CITI Public Key
		with open(get_file_path(self.citi_pgp_public_key), "rb") as f:
			gpg.import_keys(f.read())

		return gpg

	def get_sftp_client(self):
		return CitiSFTPClient(
			host=self.hostname,
			username=self.username,
			private_key_path=get_file_path(self.sftp_key),
			port=cint(self.port) or 22,
			private_key_passphrase=self.get_password("password")
			if self.password
			else None,
		)

	def create_new_file(self, file_name: str):
		r_file = frappe.new_doc("File")
		r_file.file_name = file_name
		r_file.content = file_name.encode()
		r_file.folder = "Home/Status Log"
		r_file.attached_to_doctype = "Status Log"
		r_file.attached_to_name = file_name
		r_file.file_type = "TXT"
		r_file.is_private = 1
		r_file.attached_to_field = "status_file"
		r_file.insert()
		return r_file

	def create_status_log(self, file_name: str, status_file_url: str):
		status_log = frappe.new_doc("H2H Status Log")
		status_log.source_file_name = file_name
		status_log.status_file = status_file_url
		status_log.host = self.doctype
		status_log.host_name = self.name
		status_log.save()
		return status_log

	def decrypt_file_content(
		self, file_name: str = None, file_content: str = None
	) -> str:
		if not file_content and not file_name:
			frappe.throw("File content or file name must be provided for decryption.")

		if file_name and not file_content:
			file_path = get_file_path(file_name)
			with open(file_path, "rb") as f:
				file_content = f.read().decode()

		gpg = self.init_gpg()

		decrypted_data = gpg.decrypt(
			file_content,
			passphrase=self.get_password("pgp_private_key_password")
			if self.pgp_private_key_password
			else None,
		)

		if decrypted_data.ok:
			return str(decrypted_data)
		else:
			frappe.log_error("Decryption failed", decrypted_data.stderr)
			frappe.throw("Decryption failed please check the logs for more details")

	def get_formated_response(self, file_name, content: str) -> str:
		formated_response = {}

		if file_name.upper().startswith("CITI_IN_MT940"):
			return self.format_statement_data(content, formated_response)

		root = ET.fromstring(content)
		# Define namespace
		ns = {"ns": "urn:iso:std:iso:20022:tech:xsd:pain.002.001.03"}

		payment_order = root.find(".//ns:OrgnlGrpInfAndSts/ns:OrgnlMsgId", ns)
		if payment_order is not None:
			payment_order = payment_order.text

		if file_name.upper().startswith("CITI_FILE_ACK"):
			msg_id = root.find(".//ns:OrgnlGrpInfAndSts/ns:OrgnlMsgId", ns).text
			file_status = root.find(".//ns:OrgnlGrpInfAndSts/ns:GrpSts", ns).text
			status_description = root.find(
				".//ns:OrgnlGrpInfAndSts/ns:StsRsnInf/ns:AddtlInf", ns
			).text
			payment_id = msg_id.split("_")[:-1][0]
			status = self.get_status_map(file_status)
			logs = frappe.db.get_all(
				"H2H Payment Log Summary",
				{"parent": payment_id, "parenttype": "H2H Payment Log"},
				pluck="payment_id",
			)
			if logs:
				for logid in logs:
					formated_response[logid] = {
						"unique_id": logid,
						"status": status,
						"status_code": file_status,
						"message": status_description,
					}
		elif file_name.upper().startswith(
			"CITI_ACK_ACCEPT"
		) or file_name.upper().startswith("CITI_ACK_REJECT"):
			for tx in root.findall(".//ns:TxInfAndSts", ns):
				payment_id = tx.find("ns:OrgnlInstrId", ns).text
				transaction_status = tx.find("ns:TxSts", ns).text
				status_description = tx.find("ns:StsRsnInf/ns:AddtlInf", ns).text
				reference_no = tx.find("ns:AcctSvcrRef", ns).text
				amount_tag = tx.find(".//ns:Amt/ns:InstdAmt", ns)
				amount = amount_tag.text if amount_tag is not None else ""
				currency = (
					amount_tag.attrib.get("Ccy") if amount_tag is not None else "N/A"
				)
				formated_response[payment_id] = {
					"payment_order": payment_order,
					"unique_id": payment_id,
					"status": self.get_status_map(transaction_status),
					"status_code": status_description,
					"reference_no": reference_no,
					"message": status_description,
					"amount": amount,
					"currency": currency,
				}
		else:
			frappe.throw("Unknown file type for formatting response.")

		return formated_response

	def format_statement_data(self, file_content, formated_response):
		import mt940

		try:
			transactions = mt940.parse(file_content)
			for transaction in transactions:
				transaction = frappe._dict(transaction.data)
				amount_obj = transaction.amount
				formated_response[transaction.customer_reference] = {
					"customer_reference": transaction.customer_reference,
					"unique_id": transaction.customer_reference,
					"transaction_reference": transaction.transaction_reference,
					"reference_number": transaction.bank_reference,
					"transaction_amount": cstr(amount_obj.amount),
					"currency": transaction.currency,
					"transaction_date": cstr(transaction.date),
					"transaction_description": transaction.purpose,
					"description": transaction.posting_text,
					"transaction_code": transaction.transaction_code,
					"bank_reference": transaction.bank_reference,
				}
		except Exception as e:
			frappe.log_error(
				"MT940 statement parsing failure", frappe.get_traceback(with_context=1)
			)
			formated_response["error"] = str(e)

		return formated_response

	def format_response(self, file_name, decrypted_data: str) -> str:
		formated_response = {}
		try:
			formated_response = self.get_formated_response(file_name, decrypted_data)
		except Exception:
			frappe.log_error(
				"Formatting response failed", frappe.get_traceback(with_context=True)
			)
			frappe.throw(
				"Formatting response failed please check the logs for more details"
			)

		if formated_response:
			frappe.db.set_value(
				"H2H Status Log",
				file_name,
				"formatted_data",
				json.dumps(formated_response, indent=4),
			)
			frappe.db.commit()
			frappe.get_doc("H2H Status Log", file_name).update_payment_status()

		return formated_response

	def get_status_map(self, file_status) -> dict:
		if file_status in ["ACCP", "CACC"]:
			return "Accepted"
		elif file_status in ["RJCT", "REJT"]:
			return "Rejected"

		return "Pending"

	def get_files_from_server(
		self, client: CitiSFTPClient, files: list, folder: str = "."
	):
		if not client:
			client = self.get_sftp_client()

		if not files or not isinstance(files, (str, list)):
			return

		if isinstance(files, str):
			files = [files]

		for file_name in files:
			if frappe.db.exists("H2H Status Log", {"source_file_name": file_name}):
				frappe.get_doc("H2H Status Log", file_name).format_response()
				continue
			file_path = os.path.join(folder, file_name)
			try:
				client.sftp.stat(file_path)
			except FileNotFoundError:
				frappe.log_error("File not found on SFTP server:\nFile Path", file_path)
				continue

			create_new_folder("Status Log", "Home")

			r_file = self.create_new_file(file_name)
			status_log = self.create_status_log(file_name, r_file.file_url)

			with client.sftp.open(file_path, "r") as file:
				status_file_content = file.read().decode()  # Read and decode content

				if status_file_content:
					frappe.db.set_value(
						"H2H Status Log",
						status_log.name,
						"decrypted_data",
						status_file_content,
					)
					self.write_file_content(
						get_file_path(r_file.file_url), status_file_content.encode()
					)
					# Save the Status file content to the Status Log document to avoid Data Loss
					frappe.db.commit()
			status_log.reload()
			status_log.format_response()
			frappe.db.commit()

	@frappe.whitelist()
	def force_fetch_status(self):
		self.is_h2h_enabled()
		return self.get_status_from_server(force_fetch=True)
