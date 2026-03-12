// Copyright (c) 2024, Aerele Technologies Private Limited and contributors
// For license information, please see license.txt

frappe.ui.form.on("ICICI Connector", {
	reset_endpoints(frm) {
		frm.call("reset_endpoints").then(() => {
			frm.dirty();
		});
	},
	refresh(frm) {
		frm.add_custom_button(
			__("Register"),
			() => {
				frm.call({
					method: "register",
					doc: frm.doc,
				}).then((r) => {
					if (!r.exc) {
						frm.reload_doc();
					}
				});
			},
			__("Actions")
		);
		frm.add_custom_button(
			__("Registration Status"),
			() => {
				frm.call({
					method: "registration_inquiry",
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
