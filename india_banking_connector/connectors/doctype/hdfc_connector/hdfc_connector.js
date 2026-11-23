// Copyright (c) 2026, Aerele Technologies Private Limited and contributors
// For license information, please see license.txt

frappe.ui.form.on("HDFC Connector", {
	refresh(frm) {
		if (!frm.is_new()) {
			frm.add_custom_button(__("Fetch Bank Balance"), function () {
				if (!frm.doc.partner_id) {
					frappe.msgprint({
						title: __("Missing Partner ID"),
						indicator: "orange",
						message: __("Please configure Partner ID in Balance & Statement Configuration before fetching balance.")
					});
					return;
				}
				frappe.call({
					method: "get_bank_balance",
					doc: frm.doc,
					freeze: true,
					freeze_message: __("Connecting to HDFC Bank Gateway..."),
					callback: function (r) {
						if (r.message) {
							let res = r.message;
							let html = `
								<div style="font-size: 13px;">
									<div style="display: flex; gap: 10px; margin-bottom: 15px;">
										<div style="flex: 1; background: #e8f5e9; border: 1px solid #c8e6c9; border-radius: 6px; padding: 10px;">
											<div style="font-size: 11px; color: #2e7d32; font-weight: bold;">AVAILABLE BALANCE</div>
											<div style="font-size: 18px; font-weight: bold; color: #1b5e20;">₹ ${res.available_balance !== undefined && res.available_balance !== null ? res.available_balance : "N/A"}</div>
										</div>
										<div style="flex: 1; background: #e3f2fd; border: 1px solid #bbdefb; border-radius: 6px; padding: 10px;">
											<div style="font-size: 11px; color: #1565c0; font-weight: bold;">CLEAR BALANCE</div>
											<div style="font-size: 18px; font-weight: bold; color: #0d47a1;">₹ ${res.clear_balance !== undefined && res.clear_balance !== null ? res.clear_balance : "N/A"}</div>
										</div>
										<div style="flex: 1; background: #fff3e0; border: 1px solid #ffe0b2; border-radius: 6px; padding: 10px;">
											<div style="font-size: 11px; color: #e65100; font-weight: bold;">HOLD AMOUNT</div>
											<div style="font-size: 18px; font-weight: bold; color: #bf360c;">₹ ${res.hold_amount !== undefined && res.hold_amount !== null ? res.hold_amount : "N/A"}</div>
										</div>
									</div>
									${res.bank_message ? `<div class="alert alert-warning" style="margin-bottom: 10px;"><strong>Bank Response:</strong> ${res.bank_message} (${res.error_code || ""})</div>` : ""}
									<strong>Decrypted Response:</strong>
									<pre style="background: #f8f9fa; padding: 10px; border-radius: 4px; max-height: 250px; overflow: auto; font-size: 11px;">${JSON.stringify(res.decrypted_data || res, null, 2)}</pre>
								</div>
							`;
							frappe.msgprint({
								title: __("HDFC Bank Balance Result"),
								indicator: res.server_status === "Success" ? "green" : "orange",
								message: html,
							});
						}
					},
				});
			}, __("Actions"));

			frm.add_custom_button(__("Fetch Bank Statement"), function () {
				frappe.call({
					method: "get_bank_statement",
					doc: frm.doc,
					freeze: true,
					freeze_message: __("Fetching Statement from HDFC Bank..."),
					callback: function (r) {
						if (r.message) {
							let res = r.message;
							let txns = res.bank_statements || [];
							let rows = "";
							for (let t of txns) {
								let color = t.transaction_amount < 0 ? "#c62828" : "#2e7d32";
								rows += `
									<tr>
										<td>${t.transaction_date || ""}</td>
										<td>${t.reference_number || ""}</td>
										<td>${t.transaction_description || ""}</td>
										<td style="text-align: right; font-weight: bold; color: ${color};">₹ ${t.transaction_amount}</td>
									</tr>
								`;
							}
							let html = `
								<div style="font-size: 13px;">
									${res.message ? `<div class="alert alert-${res.server_status === 'Success' ? 'success' : 'warning'}" style="margin-bottom: 10px;">${res.message}</div>` : ""}
									${txns.length > 0 ? `
										<div style="max-height: 300px; overflow-y: auto;">
											<table class="table table-bordered table-sm" style="font-size: 12px;">
												<thead>
													<tr style="background: #f1f3f5;">
														<th>Date</th>
														<th>Ref No</th>
														<th>Description</th>
														<th style="text-align: right;">Amount</th>
													</tr>
												</thead>
												<tbody>${rows}</tbody>
											</table>
										</div>
									` : `
										<pre style="background: #f8f9fa; padding: 10px; border-radius: 4px; max-height: 250px; overflow: auto; font-size: 11px;">${JSON.stringify(res.decrypted_data || res, null, 2)}</pre>
									`}
								</div>
							`;
							frappe.msgprint({
								title: __("HDFC Bank Statement Result"),
								indicator: res.server_status === "Success" ? "green" : "orange",
								message: html,
							});
						}
					},
				});
			}, __("Actions"));
		}
	},
	reset_endpoints(frm) {
		frm.call("reset_endpoints").then(() => {
			frm.dirty();
		});
	},
});
