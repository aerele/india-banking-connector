from india_banking_connector.tasks import clear_bank_status_log, clear_bank_payment_request_log, clear_duplicate_bank_request_logs

def execute():
    clear_bank_status_log()
    clear_bank_payment_request_log()
    clear_duplicate_bank_request_logs()
