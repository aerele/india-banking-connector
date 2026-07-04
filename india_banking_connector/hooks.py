app_name = "india_banking_connector"
app_title = "India Banking Connector"
app_publisher = "Aerele Technologies Private Limited"
app_description = "India Banking Connector is a unified platform that allows seamless integration with multiple bank APIs for efficient and secure financial operations."
app_email = "hello@aerele.in"
app_license = "mit"

after_install = "india_banking_connector.install.after_install"

doctype_js = {
	"Bank Account": "public/js/bank_account.js",
	"Payment Order": "public/js/payment_order.js",
}

scheduler_events = {
	"cron": {
		"*/5 * * * *": "india_banking_connector.tasks.fetch_payment_status",
	},
}

default_log_clearing_doctypes = {
	"Bank Request Log": 60,
}
