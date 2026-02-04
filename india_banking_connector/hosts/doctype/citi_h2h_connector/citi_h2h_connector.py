# Copyright (c) 2026, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

import json
import os
import stat
from pathlib import Path
from xml.dom.minidom import parseString
from xml.etree import ElementTree as ET
from xml.etree.ElementTree import Element, SubElement, tostring

import frappe
import gnupg
from frappe.core.api.file import create_new_folder
from frappe.utils import cint, cstr, flt, get_datetime, getdate
from frappe.utils.file_manager import get_file_path

from india_banking_connector.hosts.doctype.base_host import BaseHost
from india_banking_connector.hosts.doctype.citi_h2h_connector.citi_sftp_client import (
	CitiSFTPClient,
)
from india_banking_connector.utils import get_existing_doc, get_id


class CITIH2HConnector(BaseHost):
	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.doc = frappe._dict(kwargs.get("doc", {}))
		self.summary_details = {}

	def initiate_payment(self):
		self.is_h2h_enabled()

		payment_details = self.doc
		unique_id = get_id(payment_details.name)

		existing_payment = get_existing_doc("Payment Log", unique_id)

		if existing_payment:
			if existing_payment.status == "Pending Upload":
				return self.process_payment(log_id=existing_payment.name)

			return existing_payment.get_summary_details()

		log_id = self.create_payment_log(payment_details, commit=True)

		if log_id:
			return self.process_payment(log_id=log_id)
		else:
			frappe.throw("Failed to create payment log")

	@frappe.whitelist()
	def get_files_list(self, folder=None):
		if not folder:
			folder = "."
		client = self.get_sftp_client()
		folders = client.list_files(folder)

		return "<br/>".join(folders) or "Files Not Found!"

	def create_payment_log(self, payment_details, commit=False):
		payment_log_doc = frappe.new_doc("Payment Log")
		payment_log_doc.payment_log_id = get_id(self.doc.name)
		payment_log_doc.payment_status = "Pending Upload"
		payment_log_doc.host = self.doctype
		payment_log_doc.host_name = self.name

		for pd in payment_details.summary:
			payment_log_doc.append(
				"payment_summary",
				{
					"payment_id": pd.get("name", ""),
					"status": json.dumps({"payment_status": "Accepted"}),
				},
			)
		payment_log_doc.insert()

		self.make_payment_file(payment_log_doc.name)

		if commit:
			frappe.db.commit()

		return payment_log_doc.name

	def make_payment_file(self, payment_log_id):
		payment_log_doc = frappe.get_doc("Payment Log", payment_log_id)
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

			if file_content:
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
					"Payment Log", payment_log_id, f"{mot}_payment_file", file.file_url
				)

				requested_data[mot] = file_content
				file_urls[f"{mot}_payment_file"] = file.file_url

		values = file_urls
		values["request"] = json.dumps(requested_data)
		frappe.db.set_value("Payment Log", payment_log_id, values)

	def update_summary_details(self):
		file_mot = []
		payment_details = frappe._dict(self.doc)

		for summary in payment_details.summary:
			summary = frappe._dict(summary)
			mot = ""
			# Round Bank rounding decimal 2 (eg. .989 to .99)
			summary["amount"] = flt(summary.get("amount", 0.0), 2)
			if "a2a" in summary.mode_of_transfer.lower():
				mot = "a2a"
				if self.summary_details.get(mot):
					self.summary_details[mot]["summary"].append(summary)
					self.summary_details[mot]["total"] += summary.amount
				else:
					self.summary_details[mot] = {}
					self.summary_details[mot]["summary"] = [summary]
					self.summary_details[mot]["total"] = summary.amount
			elif "rtgs" in summary.mode_of_transfer.lower():
				mot = "rtgs"
				if self.summary_details.get(mot):
					self.summary_details[mot]["summary"].append(summary)
					self.summary_details[mot]["total"] += summary.amount
				else:
					self.summary_details[mot] = {}
					self.summary_details[mot]["summary"] = [summary]
					self.summary_details[mot]["total"] = summary.amount
			else:
				mot = "neft"
				if self.summary_details.get(mot):
					self.summary_details[mot]["summary"].append(summary)
					self.summary_details[mot]["total"] += summary.amount
				else:
					self.summary_details[mot] = {}
					self.summary_details[mot]["summary"] = [summary]
					self.summary_details[mot]["total"] = summary.amount

			file_mot.append(mot)

		self.to_be_generate_mot = list(set(file_mot))

	def build_xml_from_dict(self, parent, data):
		if isinstance(data, dict):
			for key, value in data.items():
				if key.startswith("@"):
					parent.set(key[1:], str(value))
					continue
				elif key == "#text":
					parent.text = str(value)
					return

				if isinstance(value, (dict, list)):
					if key.startswith("CdtTrfTxInf-"):
						key = "CdtTrfTxInf"
					child = SubElement(parent, key)
					self.build_xml_from_dict(child, value)
				else:
					child = SubElement(parent, key)
					child.text = str(value)
		elif isinstance(data, list):
			for item in data:
				item_tag = parent.tag[:-1] if parent.tag.endswith("s") else parent.tag
				child = SubElement(parent, item_tag)
				self.build_xml_from_dict(child, item)
		else:
			parent.text = str(data)

	def build_element(self, tag, value):
		attrs = {}
		text = None
		if isinstance(value, dict):
			for k in list(value.keys()):
				if k.startswith("@"):
					attrs[k[1:]] = value.pop(k)
				elif k == "#text":
					text = value.pop(k)
		elem = Element(tag, attrs)
		if text:
			elem.text = text

		self.build_xml_from_dict(elem, value)
		return elem

	def get_mode_of_transfer(self, mot):
		if mot in ["rtgs", "a2a"]:
			return "URGP"
		elif mot == "imps":
			return "IMPS"
		else:
			return "URNS"

	def get_transactions(self, mot, summary_details):
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

		xml_dict = {
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
										"Cd": "URNS",
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
						**self.get_transactions(mot, payment_dict.summary_details),
					},
				},
			}
		}

		return xml_dict

	def process_payment(self, log_id):
		self.make_payment_file(log_id)

		if self.encrypt_payment_file:
			self.encrypt_payment_files(log_id)

		if self.upload_payment_file:
			return self.upload_payment_files_to_server(log_id)

		return frappe.get_doc("Payment Log", log_id).get_summary_details()

	def encrypt_payment_files(self, log_id):
		payment_log_doc = frappe.get_doc("Payment Log", log_id)
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

		recipient_fingerprint = self.hsbc_finger_print
		signer_fingerprint = self.client_finger_print

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
			frappe.db.set_value("Payment Log", log_id, encrypted_file_urls)
		elif to_be_enc_mot:
			frappe.throw("Failed to encrypt payment file")

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

		# Import HSBC Public Key
		with open(get_file_path(self.hsbc_pgp_public_key), "rb") as f:
			gpg.import_keys(f.read())

		return gpg

	def get_not_uploaded_files(self, payment_log_doc):
		not_uploaded_files = []

		encrypted = "_encrypted_" if self.encrypt_payment_file else "_"

		if payment_log_doc.get("a2a" + encrypted + "payment_file"):
			if not payment_log_doc.uploaded_a2a:
				not_uploaded_files.append(
					("a2a", payment_log_doc.get("a2a" + encrypted + "payment_file"))
				)

		if payment_log_doc.get("neft" + encrypted + "payment_file"):
			if not payment_log_doc.uploaded_neft:
				not_uploaded_files.append(
					("neft", payment_log_doc.get("neft" + encrypted + "payment_file"))
				)

		if payment_log_doc.get("rtgs" + encrypted + "payment_file"):
			if not payment_log_doc.uploaded_rtgs:
				not_uploaded_files.append(
					("rtgs", payment_log_doc.get("rtgs" + encrypted + "payment_file"))
				)

		if payment_log_doc.get("imps" + encrypted + "payment_file"):
			if not payment_log_doc.uploaded_imps:
				not_uploaded_files.append(
					("imps", payment_log_doc.get("imps" + encrypted + "payment_file"))
				)

		return not_uploaded_files

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

	def upload_payment_files_to_server(self, log_id):
		payment_log_doc = frappe.get_doc("Payment Log", log_id)

		not_uploaded_files = self.get_not_uploaded_files(payment_log_doc)

		if not not_uploaded_files:
			payment_log_doc.reload()
			return payment_log_doc.get_summary_details()

		try:
			uploaded_count = 0
			for mot, payout_file in not_uploaded_files:
				payment_file_path = get_file_path(payout_file)
				try:
					client = self.get_sftp_client()
					source_file_name = Path(payment_file_path).name
					destination_path = os.path.join(
						self.payment_folder, source_file_name
					)
					frappe.log_error(
						f"Uploading to SFTP Path for {mot} <destination_path>",
						destination_path,
					)
					status = client.upload(
						str(payment_file_path), "/" + destination_path
					)
					if status:
						uploaded_count += 1
						field_uploaded = f"uploaded_{mot}"
						frappe.db.set_value("Payment Log", log_id, field_uploaded, 1)
						frappe.db.commit()
				except Exception:
					frappe.log_error(
						f"Payment File Upload Failed for {mot}",
						frappe.get_traceback(with_context=True),
					)
					self.update_log_status(log_id, "Pending Upload")
		except Exception:
			frappe.log_error(
				"Payment File Upload Failed",
				frappe.get_traceback(with_context=True),
			)
			self.update_log_status(log_id, "Pending Upload")
		else:
			status = (
				"Uploaded"
				if uploaded_count == len(not_uploaded_files)
				else "Pending Upload"
			)
			frappe.log_error(
				f"Payment File Upload Status for {log_id}",
				f"Uploaded {uploaded_count} out of {len(not_uploaded_files)} files.",
			)
			self.update_log_status(log_id, status)
		finally:
			client.close()

		payment_log_doc.reload()
		return payment_log_doc.get_summary_details()

	def update_log_status(self, log_id, status):
		frappe.db.set_value("Payment Log", log_id, "status", status)
		frappe.db.commit()

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
		status_log = frappe.new_doc("Status Log")
		status_log.source_file_name = file_name
		status_log.status_file = status_file_url
		status_log.host = self.doctype
		status_log.host_name = self.name
		status_log.save()
		return status_log

	def fetch_files_from_server(self):
		self.is_h2h_enabled()
		self.get_status_from_server()

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
		root = ET.fromstring(content)
		# Define namespace
		ns = {"ns": "urn:iso:std:iso:20022:tech:xsd:pain.002.001.03"}
		formated_response = {}
		if file_name.upper().startswith("CITI_FILE_ACK"):
			msg_id = root.find(".//ns:OrgnlGrpInfAndSts/ns:OrgnlMsgId", ns).text
			file_status = root.find(".//ns:OrgnlGrpInfAndSts/ns:GrpSts", ns).text
			status_description = root.find(
				".//ns:OrgnlGrpInfAndSts/ns:StsRsnInf/ns:AddtlInf", ns
			).text

			payment_id = msg_id.split("_")[:-1][0]
			status = self.get_status_map(file_status)
			logs = frappe.db.get_all(
				"Payment Log Summary",
				{"parent": payment_id, "parenttype": "Payment Log"},
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

				formated_response[payment_id] = {
					"unique_id": payment_id,
					"status": self.get_status_map(transaction_status),
					"status_code": status_description,
					"reference_no": reference_no,
					"message": status_description,
				}
		elif file_name.upper().startswith("CITI_IN_MT940"):
			pass
		else:
			frappe.throw("Unknown file type for formatting response.")

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
				"Status Log",
				file_name,
				"formatted_data",
				json.dumps(formated_response, indent=4),
			)
			frappe.db.commit()
			frappe.get_doc("Status Log", file_name).update_payment_status()

		return formated_response

	def get_status_map(self, file_status) -> dict:
		if file_status in ["ACCP", "CACC", "CACC"]:
			return "Accepted"
		elif file_status in ["RJCT", "REJT"]:
			return "Rejected"

		return "Pending"

	def get_status_from_server(self, force_fetch=False):
		"""Fetch status files from SFTP server and process them."""
		if not self.reversefeed_folder:
			if force_fetch:
				frappe.throw("Reversefeed folder is cannot be empty.")
			return

		# Skip fetching if auto_fetch is disabled and not forced
		if not self.auto_fetch and not force_fetch:
			return

		client = self.get_sftp_client()
		files = client.list_files(close=False)

		self.get_files_from_server(client, files, self.reversefeed_folder)

	def write_file_content(self, file_path: str, content: bytes):
		with open(file_path, "wb") as f:
			f.write(content)

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
			if frappe.db.exists("Status Log", {"source_file_name": file_name}):
				frappe.get_doc("Status Log", file_name).format_response()
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
						"Status Log",
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
