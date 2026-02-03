// Copyright (c) 2026, Aerele Technologies Private Limited and contributors
// For license information, please see license.txt

frappe.ui.form.on("Payment Log", {
	refresh(frm) {
		frappe.call("india_banking_connector.utils.get_default_hosts").then((r) => {
			frm.set_query("host", function (frm) {
				return {
					filters: {
						name: ["in", r.message],
					},
				};
			});
		});
	},

	pretty_format_json(frm) {
		if (!frm.is_dirty() && !!frm.doc.request) {
			let parsedData = JSON.parse(frm.doc.request);
			let transactions = Object.entries(parsedData).map(([key, value]) => ({
				key,
				...value,
			}));
			showTransactionList(transactions);
		}
	},
});

function showTransactionList(transactions) {
	let list_html = `<ul class="list-group">`;
	transactions.forEach((txn, index) => {
		list_html += `
			<li class="list-group-item">
				<button class="btn btn-link" onclick="showTransactionDetails(${index})">
					<b>Payment</b>(${txn.key}) - ₹${txn.TXN_AMOUNT}
				</button>
			</li>`;
	});
	list_html += `</ul>`;

	let listDialog = new frappe.ui.Dialog({
		title: "Transactions List",
		fields: [
			{
				fieldname: "transaction_list",
				fieldtype: "HTML",
				options: list_html,
			},
		],
		size: "large",
	});

	listDialog.show();

	window.showTransactionDetails = function (index) {
		showTransactionDetails(transactions[index]);
	};
}

function showTransactionDetails(transaction) {
	let details_html = `<table class="table table-bordered" style="width: 100%;">
		${Object.entries(transaction)
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
		title: `Transaction: ${transaction.key}`,
		fields: [
			{
				fieldname: "transaction_data",
				fieldtype: "HTML",
				options: details_html,
			},
		],
		size: "large",
	});

	detailsDialog.show();
}
