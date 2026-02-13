// Copyright (c) 2026, Aerele Technologies Private Limited and contributors
// For license information, please see license.txt

frappe.ui.form.on("Axis Bank Connector", {
	get_api_endpoints(frm) {
		frm.call("get_api_endpoints").then(() => {
			frm.dirty();
		});
	},
});
