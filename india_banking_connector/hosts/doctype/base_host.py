import json
import os
from abc import ABC, abstractmethod
from pathlib import Path
from xml.etree.ElementTree import Element, SubElement

import frappe
from frappe import bold
from frappe.model.document import Document
from frappe.utils import flt
from frappe.utils.file_manager import get_file_path

from india_banking_connector.utils import get_existing_doc, get_id


class BaseHost(Document, ABC):
	def is_h2h_enabled(self):
		if not self.active:
			frappe.throw(
				f"{bold(self.name)} is not active. Please enable the host to initiate payment."
			)

	def get_response(self, method):
		self.is_h2h_enabled()
		if method and hasattr(self, method):
			return getattr(self, method)()
		else:
			frappe.throw(f"Unknown method {method} in host {self.name}")

	def initiate_payment(self):
		self.is_h2h_enabled()

		payment_details = self.doc
		unique_id = get_id(payment_details.name)

		existing_payment = get_existing_doc("H2H Payment Log", unique_id)

		if existing_payment:
			if existing_payment.status == "Pending Upload":
				return self.process_payment(log_id=existing_payment.name)

			return existing_payment.get_summary_details()

		log_id = self.create_payment_log(payment_details, commit=True)

		if log_id:
			return self.process_payment(log_id=log_id)
		else:
			frappe.throw("Failed to create payment log")

	def get_payment_status(self):
		payment_details = frappe._dict(self.doc)
		unique_id = get_id(payment_details.name)

		existing_payment = get_existing_doc("H2H Payment Log", unique_id)

		if existing_payment:
			return existing_payment.get_summary_details(action="get_payment_status")

		return {"message": "Payment not found"}

	def create_payment_log(self, payment_details, commit=False):
		payment_log_doc = frappe.new_doc("H2H Payment Log")
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

	def update_summary_details(self):
		file_mot = set()
		payment_details = frappe._dict(self.doc)

		for summary in payment_details.summary:
			summary = frappe._dict(summary)
			mot = ""
			# Round Bank rounding decimal 2 (eg. .989 to .99)
			summary["amount"] = flt(summary.get("amount", 0.0), 2)
			if "imps" in summary.mode_of_transfer.lower() and self.enable_imps_payment:
				mot = "imps"
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

			file_mot.add(mot)

		self.to_be_generate_mot = list(file_mot)

	def process_payment(self, log_id):
		self.make_payment_file(log_id)

		if self.encrypt_payment_file:
			self.encrypt_payment_files(log_id)

		if self.upload_payment_file:
			return self.upload_payment_files_to_server(log_id)

		return frappe.get_doc("H2H Payment Log", log_id).get_summary_details()

	def fetch_files_from_server(self):
		self.is_h2h_enabled()
		self.get_status_from_server()

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

	def upload_payment_files_to_server(self, log_id):
		payment_log_doc = frappe.get_doc("H2H Payment Log", log_id)

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
					status = client.upload(
						str(payment_file_path), "/" + destination_path
					)
					if status:
						uploaded_count += 1
						field_uploaded = f"uploaded_{mot}"
						frappe.db.set_value(
							"H2H Payment Log", log_id, field_uploaded, 1
						)
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
			self.update_log_status(log_id, status)
		finally:
			client.close()

		payment_log_doc.reload()
		return payment_log_doc.get_summary_details()

	def update_log_status(self, log_id, status):
		frappe.db.set_value("H2H Payment Log", log_id, "status", status)
		frappe.db.commit()

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

	@abstractmethod
	def make_payment_file(self, log_id):
		pass

	@abstractmethod
	def encrypt_payment_files(self, log_id):
		pass

	@abstractmethod
	def get_files_from_server(self, force_fetch=False):
		pass
