import frappe, re, random, string, json
DEFAULT_CONNECTOR = ['ICICI Connector', 'HDFC Connector', 'YES Bank Connector']

@frappe.whitelist()
def get_default_connectors():
    return DEFAULT_CONNECTOR

def get_id(length: int= 10, text: str ="") -> str:
	if isinstance(length, str):
		text = length
		length = len(length)
		return text + ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
	elif isinstance(length, int):
		text = ''.join(re.findall(r'[0-9a-zA-Z]', text))
		text_length = len(text)
		if text_length >= length:
			return text[:length]
		else:
			length = length - text_length
			return text + ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def get_error_message(code):
	msg=None
	error_codes = {
		"108363" : "The entered date cannot be prior to the current date.",
		"108590" : "The header amount does not equal the sum of records in the uploaded file.",
		"101043" : "Type system exception occurred",
		"999481" : "Dear Customer, This facility is available for select customer segments only. For any further queries please write to corporatecare@icicibank.com",
		"108588" : "The total number of records is not same in header and file records.",
		"104668" : "Please select the proper files and attach again.",
		"110370" : "Please select the proper files and attach again.",
		"104344" : "The cut-off time for this transaction has already passed. This action cannot be performed with the current transaction date.",
		"999936" : "Transactions already processed with same unique ID, please use exclusive unique id for each transaction.",
		"111267" : "The record ID is not present in the file.",
		"110004" : "Enter the valid date as the selected date is a bank holiday.",
		"994006" : "OTP Validation Failed",
		"107889" : "OTP Validation Failed",
		"100901" : "Consumption limits not defined for the user. Transaction cannot be processed. Please contact the bank administrator",
		"104666" : "File with the same name is already uploaded"
 	}
	msg = error_codes.get(str(code))
	return msg

def format_payment_status(records):
	if isinstance(records, str):
		records = json.loads(records)

	keys = [
		'transaction_type',
		'network_id',
		'credit_account_number',
		'debit_account_number',
		'ifsc_code',
		'currency',
		'total_amount',
		'host_reference_number',
		'host_response_code',
		'host_response_message',
		'transaction_remarks',
		'transaction_status'
	]

	result = {}

	for row in records[1:]:
		values = row.split('|')
		row_dict = dict(zip(keys, values))
		result[row_dict['transaction_remarks']]=row_dict

	return result

def get_file_status(key):
	msg = None
	keyword = {
		"GIP" : "This is the intermediate state where GFP batches gets executed",
		"PFI" : "(Pending for insertion)This is the state where bulk has been upload and transaction is completed from front end aand awaiting for the batch process to be completed.",
		"ENT" : "Entered state for the transaction once bulk transaction is initiated",
		"MIR" : "Manual intervention required: - goes for reversal",
		"STS" : "Success",
		"FAL" : "Failure",
		"PPD" : "Partially processed",
		"REJ" : "Transaction has gone to rejected case",
		"ATH" : "status after process scheduler batch run is completed. Its before GFP batch.",
		"CRP" : "Credit reversal pending",
		"REC" : "when initiator itself canceled or recalled the txn"
	}

	msg = keyword.get(key)

	if not msg:
		msg = "Unknown issue occured"

	return msg
