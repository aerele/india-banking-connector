// Copyright (c) 2026, Aerele Technologies Private Limited and contributors
// For license information, please see license.txt

frappe.ui.form.on("CITI H2H Connector", {
	refresh(frm) {
		frm.add_custom_button("Show Files", function () {
			frm.call("get_files_list").then((r) => {
				if (!r.exc && r.message) {
					frappe.msgprint("Files List", r.message || "Invalid response!");
				}
			});
		});
	},
});
