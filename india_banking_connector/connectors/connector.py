import frappe

def get_bank_connector(bank):
    doc = frappe._dict(payload.doc)

    if bank == "ICICI Bank":
        from india_banking_connector.connectors.icici_connector import IciciConnector
        return IciciConnector

    elif bank == "HDFC Bank":
        from india_banking_connector.connectors.hdfc_connector import HdfcConnector
        return HdfcConnector

    elif bank == "AXIS Bank":
        from india_banking_connector.connectors.axis_connector import AxisConnector
        return AxisConnector

    elif bank == "YES Bank":
        from india_banking_connector.connectors.yes_bank_connector import YesBankConnector
        return YesBankConnector

    elif bank == "KOTAK Mahindra Bank":
        from india_banking_connector.connectors.kotak_mahindra_connector import KotakMahindraConnector
        return KotakMahindraConnector

    else:
        frappe.throw("Invalid Bank")

def get_connector(payload):
    bank_connector = get_bank_connector(payload.company_bank)

    class Connector(bank_connector):
        def get_response(self, method):
            if method == "get_otp":
                return self.get_otp()
            elif method == "intiate_payment":
                return self.intiate_payment()
            elif method == "payment_status":
                return self.payment_status()
            elif method == "bank_balance":
                return self.bank_balance()
            elif method == "bank_statement":
                return self.bank_statement()
            else:
                frappe.throw("Invalid Method")

    return Connector()