"""Boot entrypoint of the Sealed llm-gateway LiteLLM container.

1. Reads secrets exported by envexec (or the files in /run/sealed/secrets/llm-gateway).
2. Checks the master key, salt key and Postgres password, and builds DATABASE_URL.
3. Renders the LiteLLM config from config.yaml plus the optional provider routes in
   providers.yaml whose key secret exists and whose family is opted in
   (BYOK_ROUTES_ENABLED=true for byok, EXTERNAL_ROUTES_ENABLED=true for external).
4. Strips env vars that must never reach LiteLLM, then execs `litellm --config ...`.

The rendered config holds no secret values, only os.environ/<NAME> references.
Usage: sealed_entrypoint.py [--render-only] [litellm args...]
"""
from __future__ import annotations

import copy
import os
import re
import shutil
import sys
import tempfile
import urllib.parse
from typing import Any, Callable, Mapping, Optional

import yaml

APP_ID = "llm-gateway"
FAMILIES = ("byok", "external")
# Both families send prompts to a third party over plain TLS. byok providers claim a TEE,
# but nothing in this VM verifies their attestation, so they need the same explicit opt-in.
OPT_IN = {"byok": "BYOK_ROUTES_ENABLED", "external": "EXTERNAL_ROUTES_ENABLED"}
EXTERNAL_LABEL = "data leaves your cloud"
BYOK_LABEL = "data leaves your cloud; provider TEE attestation not verified by Sealed"
LABELS = {"byok": BYOK_LABEL, "external": EXTERNAL_LABEL}
CALLBACK = "sealed_usage.usage_logger"
WEAK_MASTER_KEYS = {"sk-1234", "sk-", ""}

# Never passed to LiteLLM: license/enterprise switches, provider env vars that arm the
# built-in pass-through routes, tracing exporters, and the Postgres password itself.
FORBIDDEN_ENV = (
    "LITELLM_LICENSE",
    "LITELLM_ENABLE_ADMIN_MCP",
    "LITELLM_DANGEROUSLY_PERMIT_WEAK_OR_UNSET_MASTER_KEY",
    "DISABLE_AIOHTTP_TRUST_ENV",
    "OPENAI_API_KEY",
    "OPENAI_API_BASE",
    "OPENAI_BASE_URL",
    "ANTHROPIC_API_KEY",
    "OLLAMA_API_BASE",
    "USE_DDTRACE",
    "LITELLM_ENABLE_PYROSCOPE",
    "SENTRY_DSN",
    "OTEL_ENDPOINT",
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
    "LMNR_PROJECT_API_KEY",
    "OLLAMA_DEBUG_LOG_REQUESTS",
    "POSTGRES_PASSWORD",
)


class ConfigError(Exception):
    """A boot precondition failed. Messages never contain secret values."""


class Secrets:
    """Secret lookup: env var (exported by envexec) first, then the secret file."""

    def __init__(self, env: Mapping[str, str], secret_dir: str) -> None:
        self._env = env
        self._dir = secret_dir

    def get(self, name: str) -> Optional[str]:
        value = self._env.get(name)
        if value is None or not value.strip():
            value = self._read_file(name)
        if value is None:
            return None
        value = value.strip("\r\n")
        return value if value.strip() else None

    def _read_file(self, name: str) -> Optional[str]:
        path = os.path.join(self._dir, name)
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return handle.read()
        except (FileNotFoundError, IsADirectoryError, PermissionError):
            return None


def require(secrets: Secrets, name: str) -> str:
    value = secrets.get(name)
    if value is None:
        raise ConfigError(f"secret {name} is missing (expected /run/sealed/secrets/{APP_ID}/{name})")
    return value


def check_master_key(value: str) -> None:
    if value in WEAK_MASTER_KEYS or not value.startswith("sk-"):
        raise ConfigError("LITELLM_MASTER_KEY must start with sk- and must not be a known default")
    if len(value) < 35 or re.search(r"\s", value):
        raise ConfigError("LITELLM_MASTER_KEY must be at least 32 characters after sk- with no whitespace")


def database_url(password: str, env: Mapping[str, str]) -> str:
    host = env.get("SEALED_DB_HOST", "llm-gateway-db")
    port = env.get("SEALED_DB_PORT", "5432")
    user = env.get("SEALED_DB_USER", "litellm")
    name = env.get("SEALED_DB_NAME", "litellm")
    quoted = urllib.parse.quote(password, safe="")
    return f"postgresql://{user}:{quoted}@{host}:{port}/{name}"


def load_yaml(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise ConfigError(f"{path} is not a YAML mapping")
    return data


def route_entry(family: str, provider: Mapping[str, Any]) -> dict[str, Any]:
    label = LABELS[family]
    return {
        "model_name": f"{family}/{provider['id']}/*",
        "litellm_params": {
            "model": "openai/*",
            "api_base": provider["api_base"],
            "api_key": f"os.environ/{provider['secret']}",
        },
        "model_info": {
            "mode": "chat",
            "sealed_route": family,
            "sealed_provider": provider["name"],
            "sealed_data_location": label,
        },
    }


def opted_in(secrets: Secrets, family: str) -> bool:
    value = secrets.get(OPT_IN[family])
    return value is not None and value.strip().lower() == "true"


def select_providers(providers: Mapping[str, Any], secrets: Secrets) -> list[tuple[str, dict[str, Any]]]:
    """Return (family, provider) pairs whose routes should be rendered, in file order."""
    selected: list[tuple[str, dict[str, Any]]] = []
    for family in FAMILIES:
        allowed = opted_in(secrets, family)
        for provider in providers.get(family) or []:
            for field in ("id", "name", "secret", "api_base"):
                if not provider.get(field):
                    raise ConfigError(f"providers.yaml: {family} entry is missing {field}")
            if allowed and secrets.get(provider["secret"]) is not None:
                selected.append((family, provider))
    return selected


def provider_secret_names(providers: Mapping[str, Any]) -> list[str]:
    return [p["secret"] for family in FAMILIES for p in providers.get(family) or []]


def render(base: Mapping[str, Any], selected: list[tuple[str, dict[str, Any]]]) -> dict[str, Any]:
    config = copy.deepcopy(dict(base))
    model_list = config.setdefault("model_list", [])
    names = {entry.get("model_name") for entry in model_list}
    for family, provider in selected:
        entry = route_entry(family, provider)
        if entry["model_name"] in names:
            raise ConfigError(f"duplicate route {entry['model_name']}")
        names.add(entry["model_name"])
        model_list.append(entry)
    callbacks = (config.get("litellm_settings") or {}).get("callbacks") or []
    if CALLBACK not in callbacks:
        raise ConfigError(f"base config must register the {CALLBACK} callback")
    check_fallbacks(config, names)
    return config


def check_fallbacks(config: Mapping[str, Any], names: set[Any]) -> None:
    """Every router fallback must go from a served route to served, local-only routes."""
    for item in (config.get("router_settings") or {}).get("fallbacks") or []:
        if not isinstance(item, dict) or len(item) != 1:
            raise ConfigError("router_settings.fallbacks entries must be {route: [routes]}")
        (source, targets), = item.items()
        if source not in names:
            raise ConfigError(f"fallback source {source} is not a route")
        for target in targets or []:
            if target not in names or not str(target).startswith("local/"):
                raise ConfigError(f"fallback target {target} must be a served local/ route")


def child_env(
    env: Mapping[str, str],
    secrets: Secrets,
    providers: Mapping[str, Any],
    selected: list[tuple[str, dict[str, Any]]],
    db_url: str,
) -> dict[str, str]:
    out = {k: v for k, v in env.items() if k not in FORBIDDEN_ENV}
    for name in provider_secret_names(providers):
        out.pop(name, None)  # only keys of rendered routes stay visible to LiteLLM
    for _, provider in selected:
        out[provider["secret"]] = secrets.get(provider["secret"]) or ""
    for name in OPT_IN.values():
        out.pop(name, None)
    out["LITELLM_MASTER_KEY"] = require(secrets, "LITELLM_MASTER_KEY")
    out["LITELLM_SALT_KEY"] = require(secrets, "LITELLM_SALT_KEY")
    out["DATABASE_URL"] = db_url
    if out.get("LITELLM_LOG", "").upper() == "DEBUG":
        out["LITELLM_LOG"] = "ERROR"  # DEBUG logs request bodies
    return out


def litellm_argv(args: list[str], config_path: str) -> list[str]:
    for arg in args:
        if arg == "--config" or arg.startswith("--config="):
            raise ConfigError("--config is set by the entrypoint; do not pass it")
    return ["litellm", "--config", config_path, *args]


def write_outputs(out_dir: str, config: Mapping[str, Any], callback_src: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    # LiteLLM loads "sealed_usage" from the directory of the config file.
    shutil.copyfile(callback_src, os.path.join(out_dir, "sealed_usage.py"))
    path = os.path.join(out_dir, "config.yaml")
    fd, tmp = tempfile.mkstemp(dir=out_dir, prefix=".config.", suffix=".yaml")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write("# Rendered by sealed_entrypoint.py at boot. Contains no secret values.\n")
            yaml.safe_dump(dict(config), handle, sort_keys=False, default_flow_style=False)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    return path


def prepare(env: Mapping[str, str], args: list[str]) -> tuple[list[str], dict[str, str], dict[str, Any]]:
    """Validate secrets, render the config, and return (argv, child env, summary)."""
    secret_dir = env.get("SEALED_SECRETS_DIR", f"/run/sealed/secrets/{APP_ID}")
    conf_dir = env.get("SEALED_LITELLM_CONF_DIR", "/etc/litellm")
    out_dir = env.get("SEALED_LITELLM_RENDER_DIR", "/run/litellm")
    secrets = Secrets(env, secret_dir)

    check_master_key(require(secrets, "LITELLM_MASTER_KEY"))
    require(secrets, "LITELLM_SALT_KEY")
    db_url = database_url(require(secrets, "POSTGRES_PASSWORD"), env)

    base = load_yaml(os.path.join(conf_dir, "config.yaml"))
    providers = load_yaml(os.path.join(conf_dir, "providers.yaml"))
    selected = select_providers(providers, secrets)
    config = render(base, selected)
    path = write_outputs(out_dir, config, os.path.join(conf_dir, "sealed_usage.py"))

    summary = {
        "config": path,
        "routes": [entry["model_name"] for entry in config["model_list"]],
        "byok_opt_in": opted_in(secrets, "byok"),
        "external_opt_in": opted_in(secrets, "external"),
    }
    return litellm_argv(args, path), child_env(env, secrets, providers, selected, db_url), summary


def main(
    argv: Optional[list[str]] = None,
    env: Optional[Mapping[str, str]] = None,
    execvpe: Callable[[str, list[str], Mapping[str, str]], Any] = os.execvpe,
) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    render_only = False
    if args and args[0] == "--render-only":
        render_only = True
        args = args[1:]
    try:
        child_argv, child, summary = prepare(dict(os.environ if env is None else env), args)
    except (ConfigError, OSError, yaml.YAMLError) as err:
        print(f"sealed-entrypoint: {err}", file=sys.stderr)
        return 2
    print(
        "sealed-entrypoint: routes=" + ",".join(summary["routes"])
        + f" byok_opt_in={str(summary['byok_opt_in']).lower()}"
        + f" external_opt_in={str(summary['external_opt_in']).lower()} config={summary['config']}",
        file=sys.stderr,
    )
    if render_only:
        return 0
    sys.stderr.flush()
    execvpe(child_argv[0], child_argv, child)
    return 0


if __name__ == "__main__":
    sys.exit(main())
