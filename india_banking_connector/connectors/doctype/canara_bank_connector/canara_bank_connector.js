// Copyright (c) 2026, Aerele Technologies Private Limited and contributors
// For license information, please see license.txt

frappe.ui.form.on("Canara Bank Connector", {
	reset_endpoints(frm) {
		frm.call("reset_endpoints").then(() => {
			frm.dirty();
		});
	},
});
