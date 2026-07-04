frappe.ui.form.on("Bank Account", {
	refresh(frm) {
		if (!(frm.doc.account_name && frm.doc.branch_code && frm.doc.bank_account_no)) return;

		frappe.call({ method: "india_banking_connector.connectors.doctype.indusind_bank_connector.indusind_bank_connector.get_indusind_connectors" }).then((r) => {
			const connectors = r.message || [];
			if (!connectors.length) return;

			const status = frm.doc.indusind_beneficiary_status;
			const can_register = !frm.doc.indusind_beneficiary_batch_id || ["Failed", "Rejected"].includes(status);
			const can_recheck = ["Pending", "Inactive"].includes(status);

			if (can_register) {
				frm.add_custom_button(__(frm.doc.indusind_beneficiary_batch_id ? "Retry Add Beneficiary" : "Add Beneficiary"), () => {
					with_connector(connectors, (connector) => {
						frappe.call({
							method: "india_banking_connector.connectors.doctype.indusind_bank_connector.indusind_bank_connector.add_beneficiary_for_bank_account",
							freeze: true,
							freeze_message: __("Registering Beneficiary..."),
							args: { bank_account: frm.doc.name, connector },
							callback: (r) => {
								show_result(__("Add Beneficiary"), r.message && r.message.status, r.message && r.message.message);
								frm.reload_doc();
							},
						});
					});
				});
			} else if (can_recheck) {
				frm.add_custom_button(__("Check Beneficiary Status"), () => {
					with_connector(connectors, (connector) => {
						frappe.call({
							method: "india_banking_connector.connectors.doctype.indusind_bank_connector.indusind_bank_connector.check_beneficiary_status_for_bank_account",
							freeze: true,
							freeze_message: __("Checking Beneficiary Status..."),
							args: { bank_account: frm.doc.name, connector },
							callback: () => {
								frm.reload_doc().then(() => {
									show_result(
										__("Beneficiary Status"),
										frm.doc.indusind_beneficiary_status,
										frm.doc.indusind_beneficiary_message
									);
								});
							},
						});
					});
				});
			}
		});
	},
});

// Inline hex rather than Frappe's named "indicator" classes - the shared
// msgprint dialog's header indicator wasn't reliably reflecting the color
// passed (seen rendering red for a "orange"-mapped status), so we render
// our own badge instead of depending on that.
const STATUS_COLOR = {
	Active: "#2e7d32",
	Accepted: "#2e7d32",
	Pending: "#b45309",
	Inactive: "#b45309",
	Failed: "#c62828",
	Rejected: "#c62828",
};

function show_result(title, status, message) {
	const color = STATUS_COLOR[status] || "#555";
	const status_text = status || __("Unknown");
	const bank_message = message && message.trim().toLowerCase() !== status_text.trim().toLowerCase() ? message : null;

	frappe.msgprint({
		title,
		message: `
			<div>
				<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${color};margin-right:6px;"></span>
				${__("Status")}: <b>${frappe.utils.escape_html(status_text)}</b>
				${bank_message ? `<div style="margin-top:6px;color:var(--text-muted);">${frappe.utils.escape_html(bank_message)}</div>` : ""}
			</div>
		`,
	});
}

function with_connector(connectors, callback) {
	if (connectors.length === 1) {
		callback(connectors[0]);
		return;
	}

	let dialog = new frappe.ui.Dialog({
		title: __("Select IndusInd Bank Connector"),
		fields: [
			{
				label: __("Connector"),
				fieldname: "connector",
				fieldtype: "Select",
				options: connectors,
				reqd: true,
			},
		],
		primary_action_label: __("Proceed"),
		primary_action(values) {
			dialog.hide();
			callback(values.connector);
		},
	});
	dialog.show();
}
