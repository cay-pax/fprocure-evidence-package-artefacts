"""Run tamper_matrix.py with HTTP 429/5xx retries on the public RPC (verification logic unchanged)."""
import sys, time, runpy, urllib.error
sys.path.insert(0, "/home/ubuntu/wt-e2e/tools/evidence-verifier")
import verify_tep
_rpc = verify_tep.rpc
def rpc(url, method, params):
    for i in range(12):
        try: return _rpc(url, method, params)
        except urllib.error.HTTPError as e:
            if e.code != 429 and e.code < 500: raise
        except (urllib.error.URLError, TimeoutError, ConnectionError): pass
        time.sleep(min(60, 2 ** i))
    return _rpc(url, method, params)
verify_tep.rpc = rpc
runpy.run_path("/home/ubuntu/paper2/eval/c2/tamper_matrix.py", run_name="__main__")
