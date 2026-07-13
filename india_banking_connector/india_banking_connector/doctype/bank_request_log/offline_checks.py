"""
Offline safe-test harness for the LOG-FIRST-THEN-UPDATE request logging + the ICICI
connector's outbound-call outcome classification.

Runs the REAL code (bank_request_log.py create/update helpers, and ICICIConnector._logged_post)
against a faked `frappe` with the HTTP layer stubbed — it NEVER calls a real bank. Not named
test_*.py so the Frappe/unittest runner never imports it (it replaces sys.modules['frappe']);
the fake is injected only under __main__.

Run with the bench venv (needs `requests`):
    /Users/karthikeyan/frappe-bench-v16/env/bin/python offline_checks.py
"""
import sys, os, types, json as _json, importlib.util

PASS = 0
FAIL = 0
HERE = os.path.dirname(os.path.abspath(__file__))
CONNECTOR_ROOT = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
BRL_PATH = os.path.join(HERE, "bank_request_log.py")
ICICI_PATH = os.path.join(
    CONNECTOR_ROOT,
    "india_banking_connector", "connectors", "doctype", "icici_connector", "icici_connector.py",
)


def check(label, cond):
    global PASS, FAIL
    if cond: PASS += 1; print(f"  PASS  {label}")
    else: FAIL += 1; print(f"  FAIL  {label}")


def load(mod_name, path):
    spec = importlib.util.spec_from_file_location(mod_name, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = m
    spec.loader.exec_module(m)
    return m


def main():
    global PASS, FAIL
    import requests
    from requests.models import Response, PreparedRequest

    # ---------------------------------------------------------------- fake frappe
    class _dict(dict):
        def __getattr__(self, k):
            try: return self[k]
            except KeyError: return None
        def __setattr__(self, k, v): self[k] = v

    inserted = []   # docs created via frappe.new_doc(...).insert()
    setvals = []    # (doctype, name, updates)

    class _NewDoc(_dict):
        def insert(self, *a, **k):
            self["name"] = self.get("name") or f"BRL-{len(inserted)+1}"
            inserted.append(self)
            return self

    class _DB:
        def exists(self, *a, **k): return True
        def get_value(self, dt, name, field=None, as_dict=False): return 0
        def set_value(self, dt, name, updates, value=None, update_modified=True):
            setvals.append((dt, name, updates if isinstance(updates, dict) else {updates: value}))
        def commit(self): pass

    frappe = types.ModuleType("frappe")
    frappe._dict = _dict
    frappe.db = _DB()
    frappe.new_doc = lambda dt: _NewDoc()
    frappe.log_error = lambda *a, **k: None
    frappe.get_traceback = lambda *a, **k: ""
    frappe._ = lambda m, *a, **k: m
    frappe.whitelist = lambda *a, **k: (lambda fn: fn)
    fmodel = types.ModuleType("frappe.model"); fdoc = types.ModuleType("frappe.model.document")
    class Document:  # noqa
        def __init__(self, *a, **k): pass
    fdoc.Document = Document; fmodel.document = fdoc
    futils = types.ModuleType("frappe.utils")
    futils.cint = lambda v: int(v or 0); futils.cstr = lambda v: "" if v is None else str(v)
    futils.flt = lambda v, p=None: float(v or 0); futils.getdate = lambda *a, **k: None
    futils.nowdate = lambda: "2026-07-13"
    fqb = types.ModuleType("frappe.query_builder"); fqb.DocType = lambda *a, **k: None
    for name, mod in [("frappe", frappe), ("frappe.model", fmodel), ("frappe.model.document", fdoc),
                      ("frappe.utils", futils), ("frappe.query_builder", fqb)]:
        sys.modules[name] = mod

    # fake india_banking_connector.utils (used by both files)
    ibc = types.ModuleType("india_banking_connector")
    ibc_utils = types.ModuleType("india_banking_connector.utils")
    ibc_utils.ResponseObject = object
    ibc_utils.decrypt = lambda x: x
    ibc_utils.encrypt = lambda x: x
    ibc_utils.get_id = lambda n, name: (name or "")[:n]
    sys.modules["india_banking_connector"] = ibc
    sys.modules["india_banking_connector.utils"] = ibc_utils

    def fake_response(status=200, body='{"ok":1}', url="https://bank.example/x"):
        r = Response(); r.status_code = status; r._content = body.encode()
        pr = PreparedRequest(); pr.url = url; pr.method = "POST"
        pr.headers = {"apikey": "SECRET"}; pr.body = "encpayload"; r.request = pr
        return r

    # ============================================================ TEST 1: real create/update log
    print("\n[connector / log helpers] create-first (Requested) then update to the right status")
    brl = load("brl_under_test", BRL_PATH)

    inserted.clear(); setvals.clear()
    log_id = brl.create_request_log(action="Initiate Payment", url="https://bank/x",
                                    payload="encbody", ref_doctype="SD Bulk Payout",
                                    ref_docname="SD-BP-1", unique_id="U1", connector=None,
                                    status="Requested")
    check("create_request_log inserts a row with status 'Requested'",
          len(inserted) == 1 and inserted[0].get("status") == "Requested")
    check("row captured url + payload before the call",
          inserted[0].get("url") == "https://bank/x" and inserted[0].get("payload") == "encbody")

    setvals.clear()
    brl.update_request_log(log_id, status="Failed", message="Connection refused")
    check("update -> status 'Failed' on connection refused",
          any(u[2].get("status") == "Failed" for u in setvals))

    setvals.clear()
    brl.update_request_log(log_id, status="Timeout", message="Read timed out")
    check("update -> status 'Timeout' on read timeout",
          any(u[2].get("status") == "Timeout" for u in setvals))

    setvals.clear()
    brl.update_request_log(log_id, status="Success", response=fake_response(200))
    ok_update = next((u[2] for u in setvals if "status" in u[2]), {})
    check("update -> status 'Success' + status_code on a real response",
          ok_update.get("status") == "Success" and str(ok_update.get("status_code")) == "200")

    # ============================================================ TEST 2: real _logged_post mapping
    print("\n[connector / _logged_post] exception -> outcome + log status classification")
    # stub the log module the connector imports, so we can watch create/update calls
    log_calls = {"created": [], "updated": []}
    fake_brl = types.ModuleType(
        "india_banking_connector.india_banking_connector.doctype.bank_request_log.bank_request_log")
    fake_brl.create_api_log = lambda *a, **k: "LOG-API"
    def _cr(**k): log_calls["created"].append(k); return "LOG-1"
    def _up(log_id, status=None, response=None, message=None):
        log_calls["updated"].append({"log_id": log_id, "status": status,
                                     "has_response": response is not None, "message": message})
    fake_brl.create_request_log = _cr
    fake_brl.update_request_log = _up
    # package scaffolding for the connector's top-level imports
    for p in ["india_banking_connector.connectors",
              "india_banking_connector.connectors.doctype",
              "india_banking_connector.india_banking_connector",
              "india_banking_connector.india_banking_connector.doctype",
              "india_banking_connector.india_banking_connector.doctype.bank_request_log"]:
        sys.modules.setdefault(p, types.ModuleType(p))
    bc_mod = types.ModuleType("india_banking_connector.connectors.bank_connector")
    class BankConnector:  # minimal stub base (no crypto)
        def __init__(self, *a, **k): pass
        def get(self, key, default=None): return getattr(self, key, default)
    bc_mod.BankConnector = BankConnector
    sys.modules["india_banking_connector.connectors.bank_connector"] = bc_mod
    sys.modules[fake_brl.__name__] = fake_brl

    icici = load("icici_under_test", ICICI_PATH)

    inst = icici.ICICIConnector(doc={}, payment_doc={}, bulk_transaction=0)
    inst.get_account_config = lambda method=None: {}   # skip payload-building; not under test
    inst.doctype = "ICICI Connector"; inst.name = "TEST-ICICI"

    def run_post(raiser):
        log_calls["created"].clear(); log_calls["updated"].clear()
        icici.requests.post = raiser
        return inst._logged_post("Initiate Payment", "https://bank/x", {"apikey": "x"}, "encbody",
                                 ref_doctype="SD Bulk Payout", ref_docname="SD-BP-1", unique_id="U1")

    # connection refused -> not_submitted / log Failed
    res = run_post(lambda *a, **k: (_ for _ in ()).throw(requests.exceptions.ConnectionError("refused")))
    check("log created BEFORE the call with status 'Requested'",
          log_calls["created"] and log_calls["created"][0].get("status") == "Requested")
    check("ConnectionError -> outcome 'not_submitted'", res["outcome"] == "not_submitted")
    check("ConnectionError -> log updated to 'Failed'",
          log_calls["updated"] and log_calls["updated"][-1]["status"] == "Failed")

    # connect timeout -> not_submitted
    res = run_post(lambda *a, **k: (_ for _ in ()).throw(requests.exceptions.ConnectTimeout("ct")))
    check("ConnectTimeout -> outcome 'not_submitted'", res["outcome"] == "not_submitted")
    check("ConnectTimeout -> log 'Failed'", log_calls["updated"][-1]["status"] == "Failed")

    # read timeout -> timeout (ambiguous)
    res = run_post(lambda *a, **k: (_ for _ in ()).throw(requests.exceptions.ReadTimeout("rt")))
    check("ReadTimeout -> outcome 'timeout' (ambiguous)", res["outcome"] == "timeout")
    check("ReadTimeout -> log 'Timeout'", log_calls["updated"][-1]["status"] == "Timeout")

    # normal response -> response / log Success
    res = run_post(lambda *a, **k: fake_response(200))
    check("HTTP response -> outcome 'response'", res["outcome"] == "response")
    check("HTTP response -> log updated to 'Success'", log_calls["updated"][-1]["status"] == "Success")
    check("timeout was passed to requests.post is enforced by BANK_HTTP_TIMEOUT constant",
          isinstance(icici.BANK_HTTP_TIMEOUT, tuple) and len(icici.BANK_HTTP_TIMEOUT) == 2)

    print(f"\n==== RESULT: {PASS} passed, {FAIL} failed ====")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
