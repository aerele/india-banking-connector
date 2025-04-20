// Copyright (c) 2025, Aerele Technologies Private Limited and contributors
// For license information, please see license.txt

frappe.listview_settings["Bank API Endpoint"] = {
  onload: function (listview) {
    listview.page.add_inner_button(__("Regenerate API Endpoint"), () => {
      frappe.call({
        method: "india_banking_connector.install.create_bank_api_endpoint",
        callback: function (r) {
          if (r.message) {
            frappe.show_alert({
              message: __("API Endpoints Regenerated"),
              indicator: "green",
            });
          }
        },
      });
    });
  },
};
