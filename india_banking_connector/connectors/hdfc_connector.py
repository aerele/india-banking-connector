import frappe
from india_banking_connector.connectors.bank_connector import BankConnector

class HDFCBankConnector(BankConnector):
    def __init__(self):
        super().__init__()