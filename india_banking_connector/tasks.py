import frappe
from frappe.utils import add_to_date, getdate


def clear_bank_status_log(days=7):
	"""Clear Bank Status Logs"""
	settings = frappe.get_single("Connector Settings")
	if not settings.clear_bank_request_log:
		return

	stale_days = settings.stale_days or 30  # Default to 30 days if not set
	try:
		count = frappe.db.count(
			"Bank Request Log",
			{
				"creation": ["<", add_to_date(getdate(), days=-stale_days)],
				"action": ["!=", "Initiate Payment"],
			},
		)
		if count > 50000:
			end = add_to_date(getdate(), days=-stale_days)
			start = add_to_date(end, days=-(days + 7))  # Delete in batches of 7 days
			frappe.db.delete(
				"Bank Request Log",
				{
					"creation": ["between", [start, end]],
					"action": ["!=", "Initiate Payment"],
				},
			)
			count = frappe.db.count(
				"Bank Request Log",
				{
					"creation": ["<", add_to_date(getdate(), days=-stale_days)],
					"action": ["!=", "Initiate Payment"],
				},
			)
			if count > 50000:
				frappe.enqueue(
					clear_bank_status_log, days=days + 7
				)  # Enqueue next batch
		else:
			frappe.db.delete(
				"Bank Request Log",
				{
					"creation": ["<", add_to_date(getdate(), days=-stale_days)],
					"action": ["!=", "Initiate Payment"],
				},
			)
	except Exception:
		frappe.log_error(title="Failed to clear Bank Request Log")


def clear_bank_payment_request_log(days=7):
	"""Clear Bank Payment Request Logs"""
	settings = frappe.get_single("Connector Settings")
	if not settings.clear_bank_request_log:
		return

	stale_days = settings.stale_days or 60  # Default to 60 days if not set
	try:
		count = frappe.db.count(
			"Bank Request Log",
			{
				"creation": ["<", add_to_date(getdate(), days=-stale_days)],
				"action": "Initiate Payment",
			},
		)
		if count > 5000:
			end = add_to_date(getdate(), days=-stale_days)
			start = add_to_date(end, days=-(days + 7))  # Delete in batches of 7 days
			frappe.db.delete(
				"Bank Request Log",
				{
					"creation": ["between", [start, end]],
					"action": ["!=", "Initiate Payment"],
				},
			)
			count = frappe.db.count(
				"Bank Request Log",
				{
					"creation": ["<", add_to_date(getdate(), days=-stale_days)],
					"action": ["!=", "Initiate Payment"],
				},
			)
			if count > 5000:
				frappe.enqueue(
					clear_bank_payment_request_log, days=days + 7
				)  # Enqueue next batch
		else:
			frappe.db.delete(
				"Bank Request Log",                                                                                                                                                                                                 
				{
					"creation": ["<", add_to_date(getdate(), days=-stale_days)],
					"action": "Initiate Payment",
				},
			)
	except Exception:
		frappe.log_error(title="Failed to clear Bank Payment Request Log")


def clear_duplicate_bank_request_logs(days=7):
	"""Clear Duplicate Bank Request Logs"""
	settings = frappe.get_single("Connector Settings")
	if not settings.clear_duplicate_bank_request_log:
		return

	stale_days = settings.duplicate_stale_days or 7  # Default to 7 days if not set
	try:
		count = frappe.db.count(
			"Bank Request Log",
			{
				"creation": ["<=", add_to_date(getdate(), days=-stale_days)],
				"is_duplicate": 1,
			},
		)
		if count > 50000:
			end = add_to_date(getdate(), days=-stale_days)
			start = add_to_date(end, days=-(days + 7))  # Delete in batches of 7 days
			frappe.db.delete(
				"Bank Request Log",
				{
					"creation": ["between", [start, end]],
					"is_duplicate": 1,
				},
			)
			count = frappe.db.count(
				"Bank Request Log",
				{
					"creation": ["<", add_to_date(getdate(), days=-stale_days)],
					"is_duplicate": 1,
				},
			)
			if count > 50000:
				frappe.enqueue(
					clear_duplicate_bank_request_logs, days=days + 7
				)  # Enqueue next batch
		else:
			frappe.db.delete(
				"Bank Request Log",
				{
					"creation": ["<=", add_to_date(getdate(), days=-stale_days)],
					"is_duplicate": 1,
				},
			)
	except Exception:
		frappe.log_error(title="Failed to clear Duplicate Bank Request Log")
