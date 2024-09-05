// Copyright (c) 2024, Aerele Technologies Private Limited and contributors
// For license information, please see license.txt

frappe.ui.form.on("Connector Settings", {
	refresh(frm) {
        frappe.call("india_banking_connector.utils.get_default_connectors").then(r => {
            frm.set_query("connector", "connectors", function(frm, cdt, cdn) {
                console.log(r.message);
                return {
                    filters: {
                        "name": ['in', r.message]
                    }
                }
            });
        });
        
    }
});