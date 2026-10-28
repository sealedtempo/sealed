# Generates vectors.json: dstack v1 RTMR3 golden vectors.
# Part "dstack" reproduces docs/notes/dstack.md section 6.3 (key provider "none", as in the upstream note).
# Part "sealed" is the exact Sealed sequence of INTERFACES.md section 6 (key provider "tpm").
# Part "reportData" covers the three tagged report_data constructions of INTERFACES.md section 3.
# Run: python3 -I vectors.py > vectors.json
import hashlib, json, struct

T = 0x08000001

def v1_pre(name, payload):
    return struct.pack('<I', T) + b':' + name.encode() + b':' + payload

def replay(digests):
    mr = bytes(48)
    for d in digests:
        mr = hashlib.sha384(mr + d).digest()
    return mr

def sequence(app_id, compose_hash, instance_id, key_provider):
    return [
        ("system-preparing", b""),
        ("app-id", app_id),
        ("compose-hash", compose_hash),
        ("gpu-policy-hash", hashlib.sha256(b"{}").digest()),
        ("instance-id", instance_id),
        ("boot-mr-done", b""),
        ("key-provider", key_provider),
        ("storage-fs", b"ext4"),
        ("storage-encrypted", b"1"),
        ("system-ready", b""),
    ]

def events_json(evs):
    return [{"imr": 3, "event_type": T, "digest": hashlib.sha384(v1_pre(n, p)).hexdigest(),
             "event": n, "event_payload": p.hex()} for n, p in evs]

compose = {"manifest_version":2,"name":"hello","runner":"docker-compose","docker_compose_file":"services:\n  web:\n    image: nginx@sha256:0000000000000000000000000000000000000000000000000000000000000000\n","gateway_enabled":False,"kms_enabled":False,"key_provider":"none","public_logs":True,"public_sysinfo":True,"public_tcbinfo":True,"allowed_envs":[],"no_instance_id":False,"secure_time":False,"storage_fs":"ext4"}
cb = json.dumps(compose, sort_keys=True, separators=(',',':'), ensure_ascii=False).encode()
ch = hashlib.sha256(cb).digest()
app_id = bytes([0x11]*20)
instance_id = bytes([0x33]*20)

dstack_evs = sequence(app_id, ch, instance_id, b'{"name":"none","id":""}')
dstack_d = [hashlib.sha384(v1_pre(n, p)).digest() for n, p in dstack_evs]
sealed_evs = sequence(app_id, ch, instance_id, b'{"name":"tpm","id":""}')
sealed_d = [hashlib.sha384(v1_pre(n, p)).digest() for n, p in sealed_evs]

def rd(tag, *fields):
    return (hashlib.sha256(tag.encode() + b"".join(fields)).digest() + bytes(32)).hex()

nonce = bytes(range(32))
pub = bytes(range(32, 64))
stack = bytes([0xaa]*32)
cfg = bytes([0xbb]*32)
signer = bytes([0xcc]*20)
nonce2 = bytes([0xdd]*32)
tlsh = bytes([0xee]*32)

print(json.dumps({
    "appIdDeadbeefDigest": hashlib.sha384(v1_pre("app-id", bytes.fromhex("deadbeef"))).hexdigest(),
    "composeBytes": cb.decode(),
    "composeHash": ch.hex(),
    "dstack": {
        "events": events_json(dstack_evs),
        "rtmr3": replay(dstack_d).hex(),
        "rtmr3BootMrDone": replay(dstack_d[:6]).hex(),
    },
    "sealed": {
        "events": events_json(sealed_evs),
        "rtmr3": replay(sealed_d).hex(),
    },
    "reportData": {
        "nonce": nonce.hex(), "ephemeralPub": pub.hex(), "stackHash": stack.hex(), "configHash": cfg.hex(),
        "enclaveSigner": signer.hex(), "nonce2": nonce2.hex(), "tlsPubKeyHash": tlsh.hex(),
        "keyRelease": rd("sealed/kb-release/v1", nonce, pub),
        "evidence": rd("sealed/evidence/v1", stack, cfg, signer, nonce2),
        "liveAttest": rd("sealed/attest/v1", nonce, tlsh, signer),
    },
}, indent=2))
