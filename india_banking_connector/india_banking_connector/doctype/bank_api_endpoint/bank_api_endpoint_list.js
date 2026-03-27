// Copyright (c) 2025, Aerele Technologies Private Limited and contributors
// For license information, please see license.txt

frappe.listview_settings["Bank API Endpoint"] = {
	onload: function (listview) {
		const container = $("<div>", {
			class: "form-message-container",
		});

		const message = $("<div>", {
			class: "form-message border-bottom yellow",
		});

		const text = $("<div>").html(
			"<b>Warning:</b> The Bank API Endpoints will be deprecated. Please update the API Endpoints table in the connector."
		);

		message.append(text);
		container.append(message);

		$(".page-form.flex").after(container);
	},
};
