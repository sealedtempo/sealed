"""Capture quotes and info from the spike VM.

usage: python3 -I capture.py <host> <out dir> <label>
Writes <label>-nonce{1,2}.txt, <label>-report_data{1,2}.txt, <label>-quote{1,2}.json, <label>-info.json, <label>-timings.json
"""
import hashlib, json, os, secrets, sys, time, urllib.request

host, out, label = sys.argv[1], sys.argv[2], sys.argv[3]
os.makedirs(out, exist_ok=True)
tim = {}

def get(path):
    t0 = time.time()
    with urllib.request.urlopen(f"http://{host}:8080{path}", timeout=120) as r:
        body = r.read()
        st = r.status
    return st, body, round(time.time() - t0, 3)

for i in (1, 2):
    nonce = secrets.token_bytes(32)
    rd = hashlib.sha256(b"sealed/spike/v1" + nonce).digest() + bytes(32)
    open(f"{out}/{label}-nonce{i}.txt", "w").write(nonce.hex() + "\n")
    open(f"{out}/{label}-report_data{i}.txt", "w").write(rd.hex() + "\n")
    st, body, dt = get("/quote?report_data=" + rd.hex())
    assert st == 200, (st, body[:300])
    open(f"{out}/{label}-quote{i}.json", "wb").write(body)
    tim[f"quote{i}_seconds"] = dt
    tim[f"quote{i}_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
st, body, dt = get("/info")
assert st == 200, (st, body[:300])
open(f"{out}/{label}-info.json", "wb").write(body)
tim["info_seconds"] = dt
tim["info_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
json.dump(tim, open(f"{out}/{label}-timings.json", "w"), indent=2)
print(json.dumps(tim))
