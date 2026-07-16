// Copyright (c) 2024, Aerele Technologies Private Limited and contributors
// For license information, please see license.txt

frappe.ui.form.on("Bank Request Log", {
	refresh(frm) {
		if (!frappe.user_roles.includes("System Manager")) {
			return;
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
