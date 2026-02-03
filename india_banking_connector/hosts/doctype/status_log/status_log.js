// Copyright (c) 2026, Aerele Technologies Private Limited and contributors
// For license information, please see license.txt

frappe.ui.form.on("Status Log", {
	refresh(frm) {
		frm.add_custom_button("Decrypt File", function () {
			frm.call("decrypt_file").then((r) => {
				frm.reload_doc();
			});
		});
		frm.add_custom_button("Get Formatted Response", function () {
			frm.call("format_response").then((r) => {
				frm.reload_doc();
			});
		});
	},
	pretty_format_json(frm) {
		if (!frm.is_dirty() && !!frm.doc.response) {
			let parsedData = JSON.parse(frm.doc.response);
			let responses = Object.entries(parsedData).map(([key, value]) => ({
				key,
				...value,
			}));
			showStatusList(responses);
		}
	},
});

function showStatusList(statuss) {
	let list_html = `<ul class="list-group">`;
	statuss.forEach((txn, index) => {
		list_html += `
            <li class="list-group-item">
                <button class="btn btn-link" onclick="showStatusDetails(${index})">
                    <b>Status[${txn.payment_order}]</b>(${txn.key}) - ₹${txn.amount}
                </button>
            </li>`;
	});
	list_html += `</ul>`;

	let listDialog = new frappe.ui.Dialog({
		title: "Statuss List",
		fields: [
			{
				fieldname: "status_list",
				fieldtype: "HTML",
				options: list_html,
			},
		],
		size: "large",
	});

	listDialog.show();

	window.showStatusDetails = function (index) {
		showStatusDetails(statuss[index]);
	};
}

/**
 * Show status details in a Frappe Dialog.
 */
function showStatusDetails(status) {
	let details_html = `<table class="table table-bordered" style="width: 100%;">
        ${Object.entries(status)
			.map(
				([key, value]) => `
            <tr>
                <td><b>${key}</b></td>
                <td>${value || "-"}</td>
            </tr>`
			)
			.join("")}
    </table>`;

	let detailsDialog = new frappe.ui.Dialog({
		title: `Status: ${status.key}`,
		fields: [
			{
				fieldname: "status_data",
				fieldtype: "HTML",
				options: details_html,
			},
		],
		size: "large",
	});

	detailsDialog.show();
}
