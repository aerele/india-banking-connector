// india_banking's own payment_order.js adds a plain "Get Status" button
// that just reloads the form with no feedback. Rather than fork that file
// (kept out of this app on purpose), rebind its click handler in place -
// this app loads after india_banking (see installed_apps), so by the time
// this refresh handler runs, india_banking's button already exists.
// Removing + re-adding (frm.remove_custom_button + add_custom_button) would
// instead append it at the end of the toolbar, after "Unlink Allocation" -
// rebinding the existing element keeps its original position.
frappe.ui.form.on("Payment Order", {
	refresh(frm) {
		if (!has_status_button(frm)) return;

		const btn = frm.custom_buttons[__("Get Status")];
		if (!btn) return;

		btn.off("click").on("click", () => {
			frappe.call({
				method: "india_banking.india_banking.doctype.india_banking_connector.india_banking_connector.get_payment_status",
				freeze: true,
				freeze_message: __("Fetching payment status..."),
				args: { payment_order: frm.doc.name },
				callback: () => {
					frm.reload_doc().then(() => show_payment_status_result(frm));
				},
			});
		});
	},
});

function has_status_button(frm) {
	if (!(frm.doc.docstatus === 1 && frm.has_perm("write"))) return false;
	return (frm.doc.summary || []).some(
		(item) => item.payment_status === "Initiated" || item.payment_status !== "Pending"
	);
}

const PAYMENT_STATUS_COLOR = {
	Processed: "#2e7d32",
	Approved: "#2e7d32",
	Initiated: "#b45309",
	Pending: "#b45309",
	Failed: "#c62828",
	Rejected: "#c62828",
};

function show_payment_status_result(frm) {
	const rows = (frm.doc.summary || [])
		.map((row) => {
			const color = PAYMENT_STATUS_COLOR[row.payment_status] || "#555";
			return `
				<tr>
					<td>${frappe.utils.escape_html(row.party || "")}</td>
					<td>${frappe.utils.escape_html(cstr(row.amount))}</td>
					<td>
						<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${color};margin-right:6px;"></span>
						${frappe.utils.escape_html(row.payment_status || "")}
					</td>
					<td>${frappe.utils.escape_html(row.message || "")}</td>
				</tr>
			`;
		})
		.join("");

	frappe.msgprint({
		title: __("Payment Status"),
		wide: true,
		message: `
			<table class="table table-bordered" style="margin:0;">
				<thead>
					<tr><th>${__("Party")}</th><th>${__("Amount")}</th><th>${__("Status")}</th><th>${__("Message")}</th></tr>
				</thead>
				<tbody>${rows}</tbody>
			</table>
		`,
	});
}
