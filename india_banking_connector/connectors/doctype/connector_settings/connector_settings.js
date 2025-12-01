// Copyright (c) 2024, Aerele Technologies Private Limited and contributors
// For license information, please see license.txt

frappe.ui.form.on("Connector Settings", {
	refresh(frm) {
		if (!frm?.grids[0]?.grid?.data?.length) {
			frm.add_custom_button(__("Generate Connector Settings"), function () {
				// When this button is clicked,
				frappe.call({
					method: "india_banking_connector.install.create_connector_settings",
					freeze: true,
					freeze_message: __("Generating Connector Settings..."),
					callback: function (r) {
						frappe.show_alert({
							message: __("Connector Settings Regenerated"),
							indicator: "green",
						});

						frm.reload_doc();
					},
				});
			});

			frappe.call("india_banking_connector.utils.get_default_connectors").then(r => {
				frm.set_query("connector", "connectors", function (frm, cdt, cdn) {
					console.log(r.message);
					return {
						filters: {
							"name": ['in', r.message]
						}
					}
				});
			});
		}
	}
});
