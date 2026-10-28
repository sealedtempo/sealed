"""Build the DSTACKSHR shared files for the Sealed runtime spike.

usage: python3 -I make_shared.py server.py <dir of the extracted dstack-0.6.1-uki.tar.gz> <out dir>
Writes app-compose.json (CJSON, INTERFACES 6; byte-identical to ../app-compose.json), .sys-config.json and
.instance_info (random instance_id_seed, host input, not committed).
"""
import base64, hashlib, json, os, secrets, sys

server_py, image_dir, out = sys.argv[1], sys.argv[2], sys.argv[3]
os.makedirs(out, exist_ok=True)

def cjson(v):
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)

IMAGE = "docker.io/library/python@sha256:5789aa194f757888f41fa3d48e14b6feaa1b57c0af0b56fcb1372d6474d3bff0"  # python:3.12-alpine index digest
script = open(server_py, encoding="utf-8").read()
assert "$" not in script and "\r" not in script
compose = {
    "services": {
        "spike": {
            "image": IMAGE,
            "command": ["python3", "-u", "-c", script],
            "ports": ["8080:8080"],
            "volumes": ["/var/run/dstack.sock:/var/run/dstack.sock:ro"],
            "restart": "always",
        }
    }
}
app_compose = {
    "allowed_envs": [],
    "docker_compose_file": cjson(compose),
    "gateway_enabled": False,
    "key_provider": "tpm",
    "key_provider_id": "",
    "kms_enabled": False,
    "local_key_provider_enabled": False,
    "manifest_version": 2,
    "name": "sealed-spike-hello",
    "no_instance_id": False,
    "public_logs": False,
    "public_sysinfo": False,
    "public_tcbinfo": True,
    "runner": "docker-compose",
    "secure_time": False,
    "storage_fs": "ext4",
}
b = cjson(app_compose).encode("utf-8")
open(os.path.join(out, "app-compose.json"), "wb").write(b)
print("stackHash", hashlib.sha256(b).hexdigest(), "len", len(b))

digest = open(os.path.join(image_dir, "digest.txt")).read().strip()
checksum = open(os.path.join(image_dir, "sha256sum.txt"), "rb").read()
meas = open(os.path.join(image_dir, "measurement.gcp.cbor"), "rb").read()
assert hashlib.sha256(checksum).hexdigest() == digest, "digest.txt != sha256(sha256sum.txt)"
vm_config = {
    "spec_version": 2,
    "os_image_hash": digest,
    "gcp_measurement": {
        "checksum_file": base64.b64encode(checksum).decode("ascii"),
        "measurement": base64.b64encode(meas).decode("ascii"),
    },
}
sys_config = {"kms_urls": [], "gateway_urls": [], "pccs_url": "", "vm_config": json.dumps(vm_config)}
open(os.path.join(out, ".sys-config.json"), "w").write(json.dumps(sys_config, indent=2))
seed = secrets.token_hex(20)
open(os.path.join(out, ".instance_info"), "w").write(json.dumps({"instance_id_seed": seed}, indent=2))
print("instance_id_seed", seed)
