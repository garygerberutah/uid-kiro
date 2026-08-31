#!/usr/bin/env python3
"""Fail closed unless live API inventory and Terraform ownership agree.

This command is intentionally read-only.  It complements the HCL inventory
precondition and declarative import block by inspecting the *current* state:

* an empty survivor id is accepted only when the state owns no HTTP API and
  live UID Portal inventory is empty;
* a declared survivor may be absent from state (the next plan imports it), or
  it must already be owned at the one stable resource address;
* an API at any other state address stops the workflow for reviewed declarative
  ``moved``/``import`` blocks instead of creating dual ownership.
* AT additionally requires the repository's sibling dev state to own zero
  API Gateway v2 APIs, custom domains or mappings, so the shared dev account
  cannot give one live gateway boundary two Terraform owners.

It does not plan, import, apply, or write state.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Mapping, Sequence


INFRA_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[6]
AUDIT_SCRIPT = INFRA_ROOT / "scripts" / "check-lambda-ingress.py"
ENV_TF_ROOTS = {
    env: (INFRA_ROOT / "envs" / env).resolve()
    for env in ("dev", "at", "prod")
}
DEV_TF_ROOT = ENV_TF_ROOTS["dev"]
STABLE_ADDRESS = (
    "module.stack.module.portal_api.aws_apigatewayv2_api.this"
)
STABLE_DOMAIN_ADDRESS = (
    "module.stack.module.portal_api.aws_apigatewayv2_domain_name.this[0]"
)
STABLE_MAPPING_ADDRESS = (
    "module.stack.module.portal_api.aws_apigatewayv2_api_mapping.this[0]"
)
STABLE_ADDRESSES = {
    "aws_apigatewayv2_api": STABLE_ADDRESS,
    "aws_apigatewayv2_domain_name": STABLE_DOMAIN_ADDRESS,
    "aws_apigatewayv2_api_mapping": STABLE_MAPPING_ADDRESS,
}
SURVIVOR_ASSIGNMENT = re.compile(
    r'^\s*api_gateway_survivor_id\s*=\s*"([a-z0-9]*)"\s*(?:#.*)?$',
    re.MULTILINE,
)
SURVIVOR_LINE = re.compile(
    r"^\s*api_gateway_survivor_id\s*=.*$", re.MULTILINE
)
DOMAIN_ASSIGNMENT = re.compile(
    r'^\s*portal_domain_name\s*=\s*"([^"]*)"\s*(?:#.*)?$',
    re.MULTILINE,
)
DOMAIN_LINE = re.compile(r"^\s*portal_domain_name\s*=.*$", re.MULTILINE)
DOMAIN_OWNERSHIP_ASSIGNMENT = re.compile(
    r'^\s*portal_domain_ownership\s*=\s*"(managed|external)"\s*(?:#.*)?$',
    re.MULTILINE,
)
DOMAIN_OWNERSHIP_LINE = re.compile(
    r"^\s*portal_domain_ownership\s*=.*$", re.MULTILINE
)
API_ID = re.compile(r"^[a-z0-9]{10}$")
HOSTNAME = re.compile(
    r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?"
)


class OwnershipError(RuntimeError):
    """The read-only ownership proof failed."""


def _run(args: Sequence[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            list(args),
            cwd=REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        raise OwnershipError(f"cannot execute {args[0]}: {exc}") from exc


def _declared_survivor(tf_root: Path) -> str:
    tfvars = tf_root / "terraform.tfvars"
    try:
        source = tfvars.read_text(encoding="utf-8")
    except OSError as exc:
        raise OwnershipError(f"cannot read {tfvars}: {exc}") from exc

    assignment_lines = SURVIVOR_LINE.findall(source)
    parsed = SURVIVOR_ASSIGNMENT.findall(source)
    if len(assignment_lines) != 1 or len(parsed) != 1:
        raise OwnershipError(
            f"{tfvars} must contain exactly one literal "
            'api_gateway_survivor_id = "..." assignment'
        )

    survivor_id = parsed[0]
    if survivor_id and not API_ID.fullmatch(survivor_id):
        raise OwnershipError(
            "api_gateway_survivor_id must be empty or a ten-character "
            "lowercase API Gateway v2 API id"
        )
    return survivor_id


def _declared_custom_domain(tf_root: Path) -> str:
    tfvars = tf_root / "terraform.tfvars"
    try:
        source = tfvars.read_text(encoding="utf-8")
    except OSError as exc:
        raise OwnershipError(f"cannot read {tfvars}: {exc}") from exc

    assignment_lines = DOMAIN_LINE.findall(source)
    parsed = DOMAIN_ASSIGNMENT.findall(source)
    if len(assignment_lines) != 1 or len(parsed) != 1:
        raise OwnershipError(
            f"{tfvars} must contain exactly one literal "
            'portal_domain_name = "..." assignment'
        )
    domain_name = parsed[0]
    if not HOSTNAME.fullmatch(domain_name):
        raise OwnershipError(
            "portal_domain_name must be one exact lower-case DNS hostname"
        )
    return domain_name


def _declared_domain_ownership(tf_root: Path) -> str:
    tfvars = tf_root / "terraform.tfvars"
    try:
        source = tfvars.read_text(encoding="utf-8")
    except OSError as exc:
        raise OwnershipError(f"cannot read {tfvars}: {exc}") from exc

    assignment_lines = DOMAIN_OWNERSHIP_LINE.findall(source)
    parsed = DOMAIN_OWNERSHIP_ASSIGNMENT.findall(source)
    if len(assignment_lines) != 1 or len(parsed) != 1:
        raise OwnershipError(
            f"{tfvars} must contain exactly one literal "
            'portal_domain_ownership = "managed|external" assignment'
        )
    return parsed[0]


def _state_gateway_resources(tf_root: Path) -> dict[str, dict[str, object]]:
    # `terraform show -json` loads every provider schema before rendering the
    # state. That made this ownership gate depend on unrelated provider plugins
    # (the historical dev root failed when hashicorp/archive was unavailable).
    # Raw state JSON contains the resource type, module, instances and ids this
    # proof needs and does not instantiate providers.
    result = _run(("terraform", f"-chdir={tf_root}", "state", "pull"))
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise OwnershipError(
            f"terraform state pull could not read the initialized state at {tf_root}: "
            + (detail or f"exit {result.returncode}")
        )
    try:
        document = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise OwnershipError("terraform state pull returned invalid JSON") from exc

    resources: dict[str, dict[str, object]] = {}
    raw_resources = document.get("resources", [])
    if not isinstance(raw_resources, list):
        raise OwnershipError("terraform state has an invalid resources shape")
    for resource in raw_resources:
        if not isinstance(resource, Mapping):
            continue
        if resource.get("mode") == "managed" and resource.get("type") in STABLE_ADDRESSES:
            module = str(resource.get("module", ""))
            resource_type = str(resource.get("type", ""))
            name = str(resource.get("name", ""))
            base_address = ".".join(
                part for part in (module, f"{resource_type}.{name}") if part
            )
            for instance in resource.get("instances", []):
                if not isinstance(instance, Mapping):
                    continue
                attributes = instance.get("attributes", {})
                if not isinstance(attributes, Mapping):
                    raise OwnershipError(
                        "an API Gateway v2 state instance has invalid attributes"
                    )
                resource_id = str(attributes.get("id", ""))
                index_key = instance.get("index_key")
                address = base_address
                if index_key is not None:
                    address += f"[{json.dumps(index_key, separators=(',', ':'))}]"
                if not address or not resource_id:
                    raise OwnershipError(
                        "an API Gateway v2 state object has no address or id"
                    )
                resources[address] = {
                    "type": resource_type,
                    "id": resource_id,
                    "attributes": dict(attributes),
                }
    return resources


def _prove_state_binding(
    survivor_id: str,
    custom_domain: str,
    domain_ownership: str,
    state_resources: Mapping[str, Mapping[str, object]],
) -> None:
    unexpected = sorted(
        address
        for address, resource in state_resources.items()
        if STABLE_ADDRESSES.get(str(resource.get("type"))) != address
    )
    if unexpected:
        rendered = ", ".join(
            f"{address}={state_resources[address].get('id')}"
            for address in unexpected
        )
        raise OwnershipError(
            "Terraform state owns API Gateway v2 resources outside the stable "
            f"survivor address ({rendered}). Reconcile them with separately "
            "reviewed declarative moved/import blocks before planning."
        )

    state_api = state_resources.get(STABLE_ADDRESS, {})
    state_id = str(state_api.get("id") or "")
    if not survivor_id:
        if state_id:
            raise OwnershipError(
                f"state records {STABLE_ADDRESS}={state_id} while "
                "api_gateway_survivor_id is empty. If the API still exists, "
                "record that exact id; if live inventory proves it absent, "
                "reconcile the stale state through a separately reviewed "
                "non-destructive state operation before planning"
            )
    elif state_id and state_id != survivor_id:
        raise OwnershipError(
            f"state owns {STABLE_ADDRESS}={state_id}, but the reviewed "
            f"api_gateway_survivor_id is {survivor_id}"
        )

    state_domain = state_resources.get(STABLE_DOMAIN_ADDRESS)
    if domain_ownership == "external" and state_domain is not None:
        raise OwnershipError(
            f"the externally owned custom domain must not be tracked at "
            f"{STABLE_DOMAIN_ADDRESS}; relinquish stale tracking through a "
            "separately reviewed non-destructive state reconciliation"
        )
    if state_domain is not None:
        attributes = state_domain.get("attributes")
        if not isinstance(attributes, Mapping) or (
            state_domain.get("id") != custom_domain
            or attributes.get("domain_name") != custom_domain
        ):
            raise OwnershipError(
                f"state custom domain at {STABLE_DOMAIN_ADDRESS} does not match "
                f"the reviewed portal_domain_name {custom_domain}"
            )

    state_mapping = state_resources.get(STABLE_MAPPING_ADDRESS)
    if state_mapping is not None:
        attributes = state_mapping.get("attributes")
        if (
            (domain_ownership == "managed" and state_domain is None)
            or not isinstance(attributes, Mapping)
            or (
                not survivor_id
                or attributes.get("api_id") != survivor_id
                or attributes.get("domain_name") != custom_domain
                or attributes.get("stage") != "$default"
                or attributes.get("api_mapping_key") not in (None, "")
            )
        ):
            raise OwnershipError(
                f"state API mapping at {STABLE_MAPPING_ADDRESS} must be the "
                "sole root mapping from the reviewed custom domain to the "
                "reviewed survivor/$default"
            )


def _tf_root(env: str, supplied: Path) -> Path:
    resolved = supplied.resolve()
    expected = ENV_TF_ROOTS[env]
    if resolved != expected:
        raise OwnershipError(
            f"--tf-root for --env {env} must resolve to this checkout's "
            f"aws/terraform/repos/utahdts/uid-portal/envs/{env} root "
            f"({expected}), not {resolved}"
        )
    return resolved


def _sibling_tf_root(env: str, supplied: Path | None) -> Path | None:
    if env != "at":
        if supplied is not None:
            raise OwnershipError(
                "--sibling-tf-root is valid only for --env at"
            )
        return None

    if supplied is None:
        raise OwnershipError(
            "--sibling-tf-root is required for --env at so the sibling dev "
            "state cannot retain an API Gateway v2 API"
        )

    resolved = supplied.resolve()
    if resolved != DEV_TF_ROOT:
        raise OwnershipError(
            "AT --sibling-tf-root must resolve to this checkout's "
            "aws/terraform/repos/utahdts/uid-portal/envs/dev root "
            f"({DEV_TF_ROOT}), not {resolved}"
        )
    return resolved


def _prove_sibling_state_empty(
    state_resources: Mapping[str, Mapping[str, object]],
) -> None:
    if not state_resources:
        return
    rendered = ", ".join(
        f"{address}={state_resources[address].get('id')}"
        for address in sorted(state_resources)
    )
    raise OwnershipError(
        "the sibling dev Terraform state must own zero "
        f"API Gateway v2 APIs, custom domains and mappings before AT may plan "
        f"({rendered}). "
        "Reconcile the dev/AT state lineage in a separately reviewed state "
        "operation; do not remove state merely to bypass this preflight."
    )


def _live_name(survivor_id: str, region: str) -> str:
    result = _run(
        (
            "aws",
            "apigatewayv2",
            "get-api",
            "--region",
            region,
            "--api-id",
            survivor_id,
            "--query",
            "Name",
            "--output",
            "text",
        )
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise OwnershipError(
            f"cannot resolve reviewed survivor {survivor_id}: "
            + (detail or f"aws exited {result.returncode}")
        )
    name = result.stdout.strip()
    if not name or name == "None":
        raise OwnershipError(f"reviewed survivor {survivor_id} has no API name")
    return name


def _prove_live_inventory(
    survivor_id: str,
    custom_domain: str,
    env: str,
    region: str,
) -> dict[str, object]:
    args = [
        sys.executable,
        str(AUDIT_SCRIPT),
        "--cardinality-only",
        "--env",
        env,
        "--region",
        region,
        "--allowed-host",
        custom_domain,
        "--json",
    ]
    if survivor_id:
        args.extend(
            ("--api-id", survivor_id, "--api-name", _live_name(survivor_id, region))
        )
    try:
        result = subprocess.run(
            args,
            cwd=REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        raise OwnershipError(f"cannot execute live inventory audit: {exc}") from exc
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        detail = (result.stderr or result.stdout).strip()
        raise OwnershipError(
            "live account/Region inventory did not return a valid JSON report: "
            + (detail or f"exit {result.returncode}")
        ) from exc
    if not isinstance(report, dict):
        raise OwnershipError("live account/Region inventory report is not an object")
    if result.returncode != 0:
        raw_findings = report.get("findings")
        detail = json.dumps(raw_findings, sort_keys=True) if raw_findings else ""
        raise OwnershipError(
            "live account/Region inventory does not match the reviewed survivor"
            + (f": {detail}" if detail else "")
        )
    if report.get("ok") is not True or report.get("mode") != "cardinality-only":
        raise OwnershipError("live account/Region inventory report is incomplete")
    return report


def _prove_live_state_binding(
    report: Mapping[str, object],
    survivor_id: str,
    custom_domain: str,
    domain_ownership: str,
    state_resources: Mapping[str, Mapping[str, object]],
) -> None:
    """Require every existing desired domain/mapping to have one state owner."""

    raw_domains = report.get("customDomains")
    raw_mappings = report.get("apiMappings")
    if not isinstance(raw_domains, list) or any(
        not isinstance(domain, str) or not domain for domain in raw_domains
    ):
        raise OwnershipError("live custom-domain inventory is unavailable or malformed")
    if not isinstance(raw_mappings, list) or any(
        not isinstance(mapping, Mapping) for mapping in raw_mappings
    ):
        raise OwnershipError("live API-mapping inventory is unavailable or malformed")

    desired_live = raw_domains.count(custom_domain) == 1
    desired_mappings = [
        mapping
        for mapping in raw_mappings
        if mapping.get("DomainName") == custom_domain
    ]
    state_domain = state_resources.get(STABLE_DOMAIN_ADDRESS)
    state_mapping = state_resources.get(STABLE_MAPPING_ADDRESS)

    if domain_ownership == "external":
        if state_domain is not None:
            raise OwnershipError(
                f"the externally owned custom domain must not be tracked at "
                f"{STABLE_DOMAIN_ADDRESS}"
            )
        if not desired_live:
            raise OwnershipError(
                f"required external custom domain {custom_domain} is absent"
            )
    elif domain_ownership != "managed":
        raise OwnershipError(
            f"unsupported portal_domain_ownership {domain_ownership!r}"
        )

    if not desired_live:
        if desired_mappings:
            raise OwnershipError(
                f"live mappings reference absent custom domain {custom_domain}"
            )
        if state_domain is not None or state_mapping is not None:
            raise OwnershipError(
                "Terraform state owns the reviewed custom domain or mapping, but "
                "the exact live resource is absent"
            )
        return

    if domain_ownership == "managed" and state_domain is None:
        raise OwnershipError(
            f"live custom domain {custom_domain} exists outside {STABLE_DOMAIN_ADDRESS}; "
            "adopt it with a separately reviewed declarative import before planning"
        )

    if not desired_mappings:
        if state_mapping is not None:
            raise OwnershipError(
                "Terraform state owns the reviewed root API mapping, but the exact "
                "live mapping is absent"
            )
        return

    if len(desired_mappings) != 1:
        raise OwnershipError(
            f"live custom domain {custom_domain} has {len(desired_mappings)} mappings"
        )
    live_mapping = desired_mappings[0]
    mapping_id = live_mapping.get("ApiMappingId")
    if not isinstance(mapping_id, str) or not mapping_id:
        raise OwnershipError("live root API mapping has no usable ApiMappingId")
    if (
        live_mapping.get("ApiId") != survivor_id
        or live_mapping.get("Stage") != "$default"
        or live_mapping.get("ApiMappingKey") not in (None, "")
    ):
        raise OwnershipError(
            "live custom domain mapping is not the reviewed survivor/$default root mapping"
        )
    if state_mapping is None:
        raise OwnershipError(
            f"live API mapping {mapping_id}/{custom_domain} exists outside "
            f"{STABLE_MAPPING_ADDRESS}; adopt it with a separately reviewed "
            "declarative import before planning"
        )
    if state_mapping.get("id") != mapping_id:
        raise OwnershipError(
            f"state mapping id {state_mapping.get('id')} does not match live "
            f"ApiMappingId {mapping_id}"
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tf-root",
        required=True,
        type=Path,
        help="repository Terraform root matching --env exactly",
    )
    parser.add_argument(
        "--sibling-tf-root",
        type=Path,
        help=(
            "initialized sibling dev Terraform root; required for AT and "
            "rejected for other environments"
        ),
    )
    parser.add_argument("--env", required=True, choices=("dev", "at", "prod"))
    parser.add_argument("--region", default="us-west-2")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        tf_root = _tf_root(args.env, args.tf_root)
        sibling_tf_root = _sibling_tf_root(args.env, args.sibling_tf_root)
        survivor_id = _declared_survivor(tf_root)
        custom_domain = _declared_custom_domain(tf_root)
        domain_ownership = _declared_domain_ownership(tf_root)
        state_resources = _state_gateway_resources(tf_root)
        _prove_state_binding(
            survivor_id,
            custom_domain,
            domain_ownership,
            state_resources,
        )
        if sibling_tf_root is not None:
            _prove_sibling_state_empty(_state_gateway_resources(sibling_tf_root))
        live_report = _prove_live_inventory(
            survivor_id,
            custom_domain,
            args.env,
            args.region,
        )
        _prove_live_state_binding(
            live_report,
            survivor_id,
            custom_domain,
            domain_ownership,
            state_resources,
        )
    except OwnershipError as exc:
        print(f"API Gateway ownership preflight failed: {exc}", file=sys.stderr)
        return 1

    if STABLE_ADDRESS in state_resources:
        state = "tracked in target Terraform state"
    elif survivor_id:
        state = "will be declaratively imported into target Terraform state"
    else:
        state = "fresh first deployment"
    rendered_id = survivor_id or "none (live UID Portal API inventory is empty)"
    print(
        "API Gateway ownership preflight passed: "
        f"survivor={rendered_id}; disposition={state}; "
        f"custom-domain={custom_domain} ({domain_ownership}); "
        f"environment/Region={args.env}/{args.region}; "
        + (
            "sibling-dev-state=zero API Gateway v2 resources"
            if sibling_tf_root is not None
            else "sibling-state=not applicable"
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
