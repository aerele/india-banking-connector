// Copyright (c) 2025, Aerele Technologies Private Limited and contributors
// For license information, please see license.txt

frappe.ui.form.on("Union Bank Connector", {
  get_api_endpoints(frm) {
    frm.call("get_api_endpoints").then(() => {
      frm.dirty();
    });
  },
});
