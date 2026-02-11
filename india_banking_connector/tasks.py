import frappe

from india_banking_connector.default import DEFAULT_HOSTS


def fetch_payment_status():
	for host in DEFAULT_HOSTS:
		host_doc_list = frappe.get_all(host, {"active": 1})
		for docname in host_doc_list:
			try:
				host_doc = frappe.get_doc(host, docname.name)
				host_doc.fetch_files_from_server()
			except Exception:
				frappe.log_error(
					f"Failed to fetch payment status for {host} - {docname.name}",
					frappe.get_traceback(with_context=True),
				)
