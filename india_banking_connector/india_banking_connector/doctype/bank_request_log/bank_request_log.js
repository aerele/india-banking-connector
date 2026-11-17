// Copyright (c) 2024, Aerele Technologies Private Limited and contributors
// For license information, please see license.txt

frappe.ui.form.on("Bank Request Log", {
	refresh(frm) {
		if (!frappe.user_roles.includes("System Manager")) {
			return;
		}

		if (
			frm.doc.action === "Initiate Payment" &&
			String(frm.doc.status_code) === "200" &&
			frm.doc.connector === "Bank of Baroda Connector"
		) {
			frm.add_custom_button(
				__("Get Payment Status"),
				() => {
					frm.call({
						method: "request_payment_status",
						doc: frm.doc,
						freeze: true,
						freeze_message: __(
							"Requesting payment status from Bank of Baroda..."
						),
					}).then((r) => {
						if (!r.exc && r.message?.log_id) {
							frappe.set_route("Form", "Bank Request Log", r.message.log_id);
						}
					});
				},
				__("Actions")
			);
		}

		// Add button to decrypt the log details
		frm.add_custom_button(
			__("Decrypt Log"),
			() => {
				frm.call({
					method: "decrypt_log",
					doc: frm.doc,
				}).then((r) => {
					if (!r.exc && r.message) {
						Object.keys(r.message).forEach((key) => {
							frm.set_value(key, r.message[key]);
						});
					}
				});
			},
			__("Actions")
		);
		// Add button to decrypt the encrypted response
		frm.add_custom_button(
			__("Decrypt Response"),
			() => {
				frm.call({
					method: "decrypt_and_set_response",
					doc: frm.doc,
				}).then((r) => {
					if (!r.exc) {
						frm.reload_doc();
					}
				});
			},
			__("Actions")
		);
	},
});
