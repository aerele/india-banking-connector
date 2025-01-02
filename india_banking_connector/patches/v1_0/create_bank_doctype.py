import frappe
def execute():
	if "erpnext" not in frappe.get_installed_apps():
		if not frappe.db.exists("DocType", "Bank"):
			doc = {
				"doctype":"DocType",
				"name":"Bank",
				"module":"India Banking Connector",
				"is_submittable":0,
				"istable":0,
				"editable_grid":0,
				"issingle":0,
				"is_tree":0,
				"custom":1,
				"permissions":[
					{
						"create":1,
						"delete":1,
						"email":1,
						"export":1,
						"print":1,
						"read":1,
						"report":1,
						"role":"System Manager",
						"share":1,
						"write":1,
						"submit":0
					}
				],
				"fields":[
					{
						"fieldtype":"Section Break"
					},
					{
						"label": "Bank Name",
						"fieldname": "bank_name",
						"fieldtype": "Data",
					}
				]
			}
			frappe.call("frappe.client.insert", doc = doc )