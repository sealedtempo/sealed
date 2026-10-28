#!/usr/bin/env python3
"""Turn a composer-built docker-compose.json into a stack that runs on a laptop.

The networks, fixed IPs, dns, proxy environment, capabilities and
security_opt of every service are kept exactly as the composer wrote them.
Only what needs the confidential VM is replaced:

- sealed-init and sealed-egress run locally built images;
- sealed-agent and caddy run the stand-in image (it writes the ready gate
  and serves HTTP), without the dstack socket, the data disk, host binds,
  devices or published ports;
- app services run the stand-in image (their entrypoint stays the composer's
  envexec wrapper, so the ready gate is exercised too).

Test-only services (prefix dc-): dc-spoofer (app-alpha, Docker's default
capabilities: the NET_RAW control), dc-router (app-alpha, NET_ADMIN, default
route via sealed-egress), dc-egress2 (a second sealed-egress whose config
allows 172.16.0.0/12) and dc-hostsvc (host network, a 0.0.0.0 listener that
stands for the dstack guest agent's 8090 listener).

usage: mkstack.py IN OUT --egress IMG --init IMG --standin IMG --host-port N
                  [--project NAME] [--writable SERVICE]...
"""
import argparse
import json
import sys

SIDECARS = {"sealed-init", "sealed-egress", "sealed-agent", "caddy",
            "sealed-mpp-payer", "sealed-verifierd"}


def fail(msg):
    print("mkstack: " + msg, file=sys.stderr)
    sys.exit(1)


def non_bind_volumes(svc):
    return [v for v in svc.get("volumes", []) if v.get("type") != "bind"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("inp")
    ap.add_argument("out")
    ap.add_argument("--egress", required=True)
    ap.add_argument("--init", required=True)
    ap.add_argument("--standin", required=True)
    ap.add_argument("--host-port", type=int, required=True)
    ap.add_argument("--project", default="sealed-dc")
    ap.add_argument("--writable", action="append", default=[],
                    help="drop read_only from this service (workaround: compose cannot "
                         "inject inline configs into a read-only container)")
    a = ap.parse_args()

    with open(a.inp) as f:
        d = json.load(f)
    d["name"] = a.project
    services = d["services"]

    for name, svc in services.items():
        if name == "sealed-init":
            svc["image"] = a.init
        elif name == "sealed-egress":
            svc["image"] = a.egress
            # Diagnostics only: keep the egress count lines readable.
            svc["logging"] = {"driver": "local"}
            if any(v.get("type") == "bind" for v in svc.get("volumes", [])):
                fail("sealed-egress has a bind mount; update mkstack.py")
        elif name == "sealed-agent":
            svc["image"] = a.standin
            svc["entrypoint"] = ["/bin/sh", "-c",
                                 "touch /run/sealed/ready/ok && exec /probe serve :7070"]
            svc.pop("command", None)
            svc.pop("devices", None)
            svc.pop("user", None)
            svc["volumes"] = non_bind_volumes(svc)
        elif name == "caddy":
            svc["image"] = a.standin
            svc["entrypoint"] = ["/probe", "serve", ":8081"]
            svc.pop("command", None)
            svc.pop("ports", None)
            svc.pop("user", None)
            svc["volumes"] = non_bind_volumes(svc)
        elif name in SIDECARS:
            fail("unexpected sidecar %s (the fixture stack has no llm-gateway)" % name)
        else:
            svc["image"] = a.standin
            if any(v.get("type") == "bind" for v in svc.get("volumes", [])):
                fail("app service %s has a bind mount (fixtures must not declare "
                     "secrets or volumes)" % name)
        if name in a.writable:
            svc.pop("read_only", None)
        # Fast teardown; the composer's grace periods only matter for real apps.
        svc["stop_grace_period"] = "2s"

    services["dc-spoofer"] = {
        "image": a.standin,
        "entrypoint": ["/probe", "serve", ":8080"],
        "networks": {"app-alpha": {"ipv4_address": "172.30.1.40"}},
        "dns": ["172.30.1.2"],
        "security_opt": ["no-new-privileges:true"],
        "stop_grace_period": "2s",
        "logging": {"driver": "local"},
    }
    # NET_ADMIN control: sets a default route via sealed-egress to see
    # whether egress (ip_forward=1 in its namespace) routes packets.
    services["dc-router"] = {
        "image": a.standin,
        "entrypoint": ["/bin/sh", "-c",
                       "ip route add default via 172.30.1.2 && exec /probe serve :8080"],
        "networks": {"app-alpha": {"ipv4_address": "172.30.1.41"}},
        "dns": ["172.30.1.2"],
        "cap_add": ["NET_ADMIN"],
        "security_opt": ["no-new-privileges:true"],
        "stop_grace_period": "2s",
        "logging": {"driver": "local"},
    }
    # A second egress on both app networks whose config opens all of
    # 172.16.0.0/12: its own interface networks (D-041 app networks) must
    # stay denied anyway (runtime/egress/README.md, destination checks).
    e2 = {
        "allowedPrivateCidrs": ["172.16.0.0/12"],
        "callers": [{"allow": ["172.30.2.1:%d" % a.host_port, "172.30.2.17:5432"],
                     "ip": "172.30.1.41", "name": "dc-router"}],
        "listen": {"dns": ":53", "proxy": ":3128", "stats": ":9100"},
        "statsReaders": [],
        "upstreamDns": ["8.8.8.8:53"],
    }
    d.setdefault("configs", {})["dc-egress2"] = {
        "content": json.dumps(e2, sort_keys=True, separators=(",", ":"))}
    services["dc-egress2"] = {
        "image": a.egress,
        "configs": [{"source": "dc-egress2", "target": "/etc/sealed/egress.json"}],
        "environment": {"SEALED_EGRESS_CONFIG": "/etc/sealed/egress.json"},
        "networks": {"app-alpha": {"ipv4_address": "172.30.1.50"},
                     "app-bravo": {"ipv4_address": "172.30.2.50"}},
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "stop_grace_period": "2s",
        "logging": {"driver": "local"},
    }
    services["dc-hostsvc"] = {
        "image": a.standin,
        "entrypoint": ["/probe", "serve", "0.0.0.0:%d" % a.host_port],
        "network_mode": "host",
        "stop_grace_period": "2s",
        "logging": {"driver": "local"},
    }

    with open(a.out, "w") as f:
        json.dump(d, f, indent=1, sort_keys=True)
        f.write("\n")


if __name__ == "__main__":
    main()
