"""Analyse a dstack GetQuote capture from the Sealed runtime spike.

usage: python3 -I check_capture.py <getquote.json> <report_data hex> <app-compose.json> [info.json]
example: python3 -I check_capture.py ../captures/boot1-getquote1.json "$(cat ../captures/boot1-report_data1.txt)" \
           ../app-compose.json ../captures/boot1-info.json
Prints a JSON report; exits 1 if any required check fails.
"""
import hashlib, json, struct, sys

quote_path, want_rd, compose_path = sys.argv[1], sys.argv[2].lower(), sys.argv[3]
info_path = sys.argv[4] if len(sys.argv) > 4 else None

resp = json.load(open(quote_path))
q = bytes.fromhex(resp["quote"])
stack_hash = hashlib.sha256(open(compose_path, "rb").read()).hexdigest()
out = {"quote_len": len(q), "stack_hash": stack_hash}
fail = []

# ---- header (48 bytes) ----
version, ak_type, tee_type = struct.unpack_from("<HHI", q, 0)
qe_svn, pce_svn = struct.unpack_from("<HH", q, 8)
out["header"] = {
    "version": version, "att_key_type": ak_type, "tee_type": hex(tee_type),
    "qe_svn": qe_svn, "pce_svn": pce_svn,
    "qe_vendor_id": q[12:28].hex(), "user_data": q[28:48].hex(),
}
off = 48
if version == 5:
    body_type, body_size = struct.unpack_from("<HI", q, off)
    out["header"]["v5_body_type"], out["header"]["v5_body_size"] = body_type, body_size
    off += 6
    body_len = body_size
else:
    body_len = 584
body = q[off:off + body_len]
fields = [("tee_tcb_svn", 16), ("mrseam", 48), ("mrsignerseam", 48), ("seam_attributes", 8),
          ("td_attributes", 8), ("xfam", 8), ("mrtd", 48), ("mrconfigid", 48), ("mrowner", 48),
          ("mrownerconfig", 48), ("rtmr0", 48), ("rtmr1", 48), ("rtmr2", 48), ("rtmr3", 48),
          ("reportdata", 64)]
if body_len == 648:
    fields += [("tee_tcb_svn2", 16), ("mrservicetd", 48)]
b = {}
p = 0
for name, n in fields:
    b[name] = body[p:p + n].hex()
    p += n
assert p == body_len, (p, body_len)
out["body"] = b
off += body_len

# TD_ATTRIBUTES / XFAM decoded (little-endian u64)
tda = int.from_bytes(bytes.fromhex(b["td_attributes"]), "little")
xfam = int.from_bytes(bytes.fromhex(b["xfam"]), "little")
out["td_attributes_u64"] = hex(tda)
out["td_attributes_bits"] = {
    "DEBUG(bit0)": tda & 1, "SEPT_VE_DISABLE(bit28)": (tda >> 28) & 1,
    "PKS(bit30)": (tda >> 30) & 1, "KL(bit31)": (tda >> 31) & 1,
    "PERFMON(bit63)": (tda >> 63) & 1,
    "other_set_bits": [i for i in range(64) if (tda >> i) & 1 and i not in (0, 28, 30, 31, 63)],
}
out["xfam_u64"] = hex(xfam)
out["xfam_set_bits"] = [i for i in range(64) if (xfam >> i) & 1]
if tda & 1:
    fail.append("TD DEBUG bit set")
if b["mrsignerseam"] != "00" * 48:
    fail.append("mr_signer_seam not zero")

# ---- signature data and padding ----
sig_len = struct.unpack_from("<I", q, off)[0]
sig_start = off + 4
sig_end = sig_start + sig_len
out["signature_data_len"] = sig_len
out["signed_region_len"] = off  # header + body that the attestation key signs
out["declared_end"] = sig_end
out["trailing_bytes_after_signature"] = len(q) - sig_end
tail = q[sig_end:]
out["trailing_all_zero"] = all(x == 0 for x in tail) if tail else None
sd = q[sig_start:sig_end]
if len(sd) >= 134:
    cert_type, cert_size = struct.unpack_from("<HI", sd, 128)
    out["sig"] = {"ecdsa_sig_len": 64, "attest_pubkey_len": 64,
                  "outer_cert_data_type": cert_type, "outer_cert_data_size": cert_size}
    cd = sd[134:134 + cert_size]
    if cert_type == 6:
        qe_report = cd[:384]
        qe_auth_len = struct.unpack_from("<H", cd, 384 + 64)[0]
        p2 = 384 + 64 + 2 + qe_auth_len
        inner_type, inner_size = struct.unpack_from("<HI", cd, p2)
        chain = cd[p2 + 6:p2 + 6 + inner_size]
        out["sig"].update({"qe_auth_data_len": qe_auth_len, "inner_cert_data_type": inner_type,
                           "inner_cert_data_size": inner_size,
                           "pem_certs": chain.count(b"-----BEGIN CERTIFICATE-----"),
                           "qe_report_mrenclave": qe_report[64:96].hex(),
                           "qe_report_mrsigner": qe_report[128:160].hex(),
                           "qe_report_isvprodid": struct.unpack_from("<H", qe_report, 256)[0],
                           "qe_report_isvsvn": struct.unpack_from("<H", qe_report, 258)[0]})
        out["sig"]["sig_data_consumed"] = 134 + 384 + 64 + 2 + qe_auth_len + 6 + inner_size

# ---- report_data ----
out["reportdata_matches"] = b["reportdata"] == want_rd
if not out["reportdata_matches"]:
    fail.append("REPORTDATA != requested report_data")
if resp.get("report_data", "").lower() != want_rd:
    fail.append("response report_data field != requested")

# ---- event log ----
ev = json.loads(resp["event_log"])
T = (0x08000001).to_bytes(4, "little")
seq = []
regs = {i: bytes(48) for i in range(4)}
for e in ev:
    d = bytes.fromhex(e["digest"])
    imr = e["imr"]
    regs[imr] = hashlib.sha384(regs[imr] + d).digest()
    if imr == 3:
        if e["event_type"] != 0x08000001 or e.get("version", 1) != 1:
            fail.append(f"unexpected RTMR3 event type/version {e}")
        payload = bytes.fromhex(e["event_payload"])
        pre = T + b":" + e["event"].encode() + b":" + payload
        if hashlib.sha384(pre).hexdigest() != e["digest"].lower():
            fail.append(f"v1 digest mismatch for {e['event']}")
        disp = payload.decode() if e["event"] in ("key-provider", "storage-fs", "storage-encrypted") else payload.hex()
        seq.append({"event": e["event"], "payload_len": len(payload), "payload": disp, "digest": e["digest"]})
out["rtmr3_events"] = seq
out["imr_event_counts"] = {i: sum(1 for e in ev if e["imr"] == i) for i in range(4)}
for i in range(4):
    out[f"replay_rtmr{i}"] = regs[i].hex()
    out[f"replay_rtmr{i}_matches_quote"] = regs[i].hex() == b[f"rtmr{i}"]
if not out["replay_rtmr3_matches_quote"]:
    fail.append("RTMR3 replay != quote RTMR3")
want_seq = ["system-preparing", "app-id", "compose-hash", "gpu-policy-hash", "instance-id", "boot-mr-done",
            "key-provider", "storage-fs", "storage-encrypted", "system-ready"]
out["sequence_matches_interfaces_6"] = [s["event"] for s in seq] == want_seq
if not out["sequence_matches_interfaces_6"]:
    fail.append("RTMR3 event sequence differs from INTERFACES 6")
ch = [s for s in seq if s["event"] == "compose-hash"]
out["compose_hash_event"] = ch[0]["payload"] if ch else None
if not ch or ch[0]["payload"] != stack_hash:
    fail.append("compose-hash event != stackHash")
kp = [s for s in seq if s["event"] == "key-provider"]
if not kp or kp[0]["payload"] != '{"name":"tpm","id":""}':
    fail.append("key-provider payload unexpected")
appid = [s for s in seq if s["event"] == "app-id"]
out["app_id_is_compose_prefix"] = bool(appid) and appid[0]["payload"] == stack_hash[:40]
# non-RTMR3 event names (firmware CCEL)
out["ccel_events"] = [{"imr": e["imr"], "event_type": hex(e["event_type"]), "event": e.get("event", ""),
                       "payload_len": len(e.get("event_payload", "")) // 2} for e in ev if e["imr"] != 3]

out["measurements_concat"] = "0x" + b["mrtd"] + b["rtmr0"] + b["rtmr1"] + b["rtmr2"]
out["quote_sha256"] = hashlib.sha256(q).hexdigest()

if info_path:
    info = json.load(open(info_path))
    tcb = json.loads(info["tcb_info"]) if isinstance(info.get("tcb_info"), str) else info.get("tcb_info")
    out["info"] = {k: info.get(k) for k in ("app_id", "instance_id", "compose_hash", "os_image_hash",
                                            "key_provider_info", "cloud_vendor", "cloud_product", "app_name",
                                            "device_id", "mr_aggregated")}
    if tcb:
        out["info"]["tcb_regs_match_quote"] = all(tcb.get(k, "").lower() == b[k] for k in ("mrtd", "rtmr0", "rtmr1", "rtmr2"))
        out["info"]["tcb_app_compose_matches_file"] = tcb.get("app_compose") == open(compose_path).read()
    if info.get("compose_hash") and info["compose_hash"].lower().removeprefix("0x") != stack_hash:
        fail.append("info.compose_hash != stackHash")

out["failures"] = fail
print(json.dumps(out, indent=2))
sys.exit(1 if fail else 0)
