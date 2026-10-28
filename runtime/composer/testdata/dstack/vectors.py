import hashlib, json, struct
T = 0x08000001
def v1_pre(name, payload):
    return struct.pack('<I', T) + b':' + name.encode() + b':' + payload
def v2_pre(name, payload):
    # JCS: keys sorted, compact
    return json.dumps({"name": name, "payload": payload.hex(), "type": T}, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
def replay(digests, n=48, h=hashlib.sha384):
    mr = bytes(n)
    for d in digests:
        mr = h(mr + d).digest()
    return mr

print("v1 preimage app-id deadbeef:", v1_pre("app-id", bytes.fromhex("deadbeef")).hex())
print("v1 sha384 app-id deadbeef:", hashlib.sha384(v1_pre("app-id", bytes.fromhex("deadbeef"))).hexdigest())
print("v2 preimage compose-hash abcd:", v2_pre("compose-hash", bytes.fromhex("abcd")).decode())
print("v2 sha384 compose-hash abcd:", hashlib.sha384(v2_pre("compose-hash", bytes.fromhex("abcd"))).hexdigest())

compose = {"manifest_version":2,"name":"hello","runner":"docker-compose","docker_compose_file":"services:\n  web:\n    image: nginx@sha256:0000000000000000000000000000000000000000000000000000000000000000\n","gateway_enabled":False,"kms_enabled":False,"key_provider":"none","public_logs":True,"public_sysinfo":True,"public_tcbinfo":True,"allowed_envs":[],"no_instance_id":False,"secure_time":False,"storage_fs":"ext4"}
cb = json.dumps(compose, sort_keys=True, separators=(',',':'), ensure_ascii=False).encode()
ch = hashlib.sha256(cb).digest()
print("sample compose bytes:", cb.decode())
print("sample compose sha256:", ch.hex())
gpu_policy_hash = hashlib.sha256(b"{}").digest()
print("gpu-policy-hash default (sha256 of '{}'):", gpu_policy_hash.hex())
app_id = bytes([0x11]*20)
instance_id = bytes([0x33]*20)
kp = json.dumps({"name":"none","id":""}, separators=(',',':')).encode()
print("key-provider payload none:", kp.decode())
events = [
 ("system-preparing", b""),
 ("app-id", app_id),
 ("compose-hash", ch),
 ("gpu-policy-hash", gpu_policy_hash),
 ("instance-id", instance_id),
 ("boot-mr-done", b""),
 ("key-provider", kp),
 ("storage-fs", b"ext4"),
 ("storage-encrypted", b"1"),
 ("system-ready", b""),
]
d384 = [hashlib.sha384(v1_pre(n,p)).digest() for n,p in events]
d256 = [hashlib.sha256(v1_pre(n,p)).digest() for n,p in events]
for (n,p),d in zip(events,d384):
    print(f"  {n:18s} payload={p.hex() or '(empty)'} sha384={d.hex()}")
print("RTMR3 replay (v1, all events):", replay(d384).hex())
print("RTMR3 replay up to boot-mr-done:", replay(d384[:6]).hex())
print("PCR14 sha256 replay (v1, all events):", replay(d256, 32, hashlib.sha256).hex())
