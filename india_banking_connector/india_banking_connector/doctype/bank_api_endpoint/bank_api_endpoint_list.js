// Copyright (c) 2025, Aerele Technologies Private Limited and contributors
// For license information, please see license.txt

frappe.listview_settings["Bank API Endpoint"] = {
	onload: (listview) => {
		listview.page.add_inner_button(__("Regenerate API Endpoints"), () => {
			frappe.call({
				method: "india_banking_connector.install.create_bank_api_endpoint",
				callback: (r) => {
					if (!r.err && !r.error) {
						frappe.show_alert({
							message: __("API Endpoints Regenerated. Please refresh this page."),
							indicator: "green",
						});
					}
				},
			});
		});
	},
};
