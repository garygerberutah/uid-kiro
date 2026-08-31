#!/usr/bin/env python3
"""Guarded full-stack Terraform planner/applicator for AT and production.

The public entry points are full-build-tf-at.sh and full-build-tf-prod.sh.
This program never issues an AWS delete call, never uses Terraform destroy or
targeting, and never mutates State-owned infrastructure.  Explicit
``--delete-recreate`` selectors are implemented with Terraform ``-replace`` in
an otherwise complete plan.  ``--allow-delete`` only acknowledges a delete
already required by the checked-in configuration; it cannot target a delete.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
INFRA_ROOT = SCRIPT_DIR.parent
REPO_ROOT = SCRIPT_DIR.parents[5]
BOUNDARY_SCRIPT = SCRIPT_DIR / "check-state-owned-boundary.py"
OWNERSHIP_SCRIPT = SCRIPT_DIR / "check-api-gateway-ownership.py"
MANIFEST = INFRA_ROOT / "state-owned-resources.json"
TERRAFORM_VERSION = "1.15.8"
PLAN_MAX_AGE = timedelta(minutes=30)

ENVIRONMENTS = {
    "at": {
        "account_id": "705157108110",
        "region": "us-west-2",
        "tf_root": INFRA_ROOT / "envs" / "at",
        "sibling_root": INFRA_ROOT / "envs" / "dev",
        "api_name": "uid-dev-api-gateway",
        "allowed_host": "api.uid-dev.utah.gov",
        "domain_name": "api.uid-dev.utah.gov",
        "domain_ownership": "external",
        "certificate_arn": "arn:aws:acm:us-west-2:705157108110:certificate/5b17baae-453a-4418-81e8-788e8336c3de",
        "lambda_prefix": "uid-portal-at-",
    },
    "prod": {
        "account_id": "281669077180",
        "region": "us-west-2",
        "tf_root": INFRA_ROOT / "envs" / "prod",
        "sibling_root": None,
        "api_name": "uid-prod-api-gateway",
        "allowed_host": "portal-api.uid.utah.gov",
        "domain_name": "portal-api.uid.utah.gov",
        "domain_ownership": "managed",
        "certificate_arn": "arn:aws:acm:us-west-2:REPLACE_ME:certificate/REPLACE_ME",
        "lambda_prefix": "uid-portal-prod-",
    },
}

# These stateless/application-control resources are the lower-risk class.
# Other approved application resources are marked application-hold: they still
# receive an individual selector, but Terraform lifecycle/prevent_destroy and
# the complete reviewed plan must authorize their destructive transition.
REPLACEABLE_TYPES = frozenset(
    {
        "aws_apigatewayv2_authorizer",
        "aws_apigatewayv2_integration",
        "aws_apigatewayv2_route",
        "aws_apigatewayv2_stage",
        "aws_cloudwatch_dashboard",
        "aws_cloudwatch_log_metric_filter",
        "aws_cloudwatch_metric_alarm",
        "aws_iam_role",
        "aws_iam_role_policy",
        "aws_iam_role_policy_attachment",
        "aws_lambda_alias",
        "aws_lambda_function",
        "aws_lambda_layer_version",
        "aws_lambda_permission",
        "aws_lambda_provisioned_concurrency_config",
        "aws_scheduler_schedule",
        "aws_scheduler_schedule_group",
        "terraform_data",
    }
)
HELD_TYPES = frozenset(
    {
        "aws_apigatewayv2_api",
        "aws_apigatewayv2_api_mapping",
        "aws_apigatewayv2_domain_name",
        "aws_cloudfront_response_headers_policy",
        "aws_cloudwatch_log_group",
        "aws_db_proxy",
        "aws_db_proxy_default_target_group",
        "aws_db_proxy_target",
        "aws_sns_topic",
        "aws_sns_topic_subscription",
        "aws_sqs_queue",
    }
)
EXPECTED_COUNTS = {
    "aws_apigatewayv2_api": 1,
    "aws_apigatewayv2_api_mapping": 1,
    "aws_apigatewayv2_integration": 42,
    "aws_apigatewayv2_route": 42,
    "aws_apigatewayv2_stage": 1,
    "aws_lambda_alias": 49,
    "aws_lambda_function": 49,
    "aws_scheduler_schedule": 4,
}


class BuildError(RuntimeError):
    pass


@dataclass(frozen=True)
class Instance:
    address: str
    display_address: str
    selector: str
    resource_type: str
    disposition: str
    arns: frozenset[str]


def _run(
    args: Sequence[str],
    *,
    cwd: Path = REPO_ROOT,
    capture: bool = False,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            list(args),
            cwd=cwd,
            input=input_text,
            text=True,
            capture_output=capture,
            check=False,
        )
    except OSError as exc:
        raise BuildError(f"cannot execute {args[0]!r}: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise BuildError(
            f"command failed ({result.returncode}): {' '.join(args)}"
            + (f"\n{detail}" if detail else "")
        )
    return result


def _load_boundary_module() -> Any:
    spec = importlib.util.spec_from_file_location("uid_state_boundary", BOUNDARY_SCRIPT)
    if spec is None or spec.loader is None:
        raise BuildError("cannot load State-owned boundary checker")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


BOUNDARY = _load_boundary_module()
POLICY = BOUNDARY.load_ownership_policy(MANIFEST)


def _leaf_strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for child in value.values():
            yield from _leaf_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _leaf_strings(child)


def _index_suffix(value: Any, *, sanitized: bool = False) -> str:
    if value is None:
        return ""
    if sanitized and isinstance(value, str):
        value = "sha256:" + hashlib.sha256(value.encode()).hexdigest()[:16]
    return "[" + json.dumps(value, ensure_ascii=True, separators=(",", ":")) + "]"


def _selector(address: str) -> str:
    return "r-" + hashlib.sha256(address.encode()).hexdigest()[:16]


def _is_exact_protected(resource_type: str, attributes: Mapping[str, Any]) -> bool:
    values = tuple(_leaf_strings(attributes))
    return any(
        target.matches_type(resource_type)
        and any(identifier in value for value in values for identifier in target.identifiers)
        for target in POLICY.targets
    )


def _disposition(resource_type: str, attributes: Mapping[str, Any]) -> str:
    if (
        BOUNDARY.is_network_resource(resource_type)
        or POLICY.protects_type(resource_type)
        or _is_exact_protected(resource_type, attributes)
    ):
        return "state-owned"
    if resource_type in REPLACEABLE_TYPES:
        return "replaceable"
    if resource_type in HELD_TYPES or resource_type.startswith("aws_s3_"):
        return "application-hold"
    if BOUNDARY.is_approved_managed_resource(resource_type):
        return "application-hold"
    return "blocker-unclassified"


def parse_state(document: Mapping[str, Any]) -> tuple[list[Instance], str, int]:
    lineage = document.get("lineage")
    serial = document.get("serial")
    resources = document.get("resources")
    if not isinstance(lineage, str) or not lineage:
        raise BuildError("Terraform state has no lineage")
    if not isinstance(serial, int) or serial < 0:
        raise BuildError("Terraform state has no valid serial")
    if not isinstance(resources, list):
        raise BuildError("Terraform state has no resources list")
    instances: list[Instance] = []
    selectors: set[str] = set()
    for resource in resources:
        if not isinstance(resource, Mapping) or resource.get("mode", "managed") != "managed":
            continue
        module = resource.get("module", "")
        resource_type = resource.get("type")
        name = resource.get("name")
        raw_instances = resource.get("instances")
        if not all(isinstance(value, str) for value in (module, resource_type, name)):
            raise BuildError("Terraform state contains a malformed managed resource")
        if not isinstance(raw_instances, list):
            raise BuildError(f"Terraform state has malformed {resource_type}.{name}")
        base = ".".join(part for part in (module, f"{resource_type}.{name}") if part)
        for raw in raw_instances:
            if not isinstance(raw, Mapping):
                raise BuildError(f"Terraform state has malformed instance {base}")
            if raw.get("deposed") not in (None, "") or raw.get("status") == "tainted":
                raise BuildError(f"{base} is tainted/deposed; reconcile it before building")
            attributes = raw.get("attributes")
            if not isinstance(attributes, Mapping):
                attributes = {}
            address = base + _index_suffix(raw.get("index_key"))
            display = base + _index_suffix(raw.get("index_key"), sanitized=True)
            token = _selector(address)
            if token in selectors:
                raise BuildError("resource selector collision")
            selectors.add(token)
            arns = frozenset(
                value for value in _leaf_strings(attributes) if value.startswith("arn:")
            )
            instances.append(
                Instance(
                    address,
                    display,
                    token,
                    resource_type,
                    _disposition(resource_type, attributes),
                    arns,
                )
            )
    return sorted(instances, key=lambda item: item.address), lineage, serial


def resolve_selectors(
    instances: Sequence[Instance], selectors: Iterable[str], operation: str
) -> dict[str, Instance]:
    by_token = {item.selector: item for item in instances}
    selected: dict[str, Instance] = {}
    for token in selectors:
        item = by_token.get(token)
        if item is None:
            raise BuildError(f"unknown or stale resource selector {token!r}; rerun --dry-run")
        if item.disposition not in {"replaceable", "application-hold"}:
            raise BuildError(
                f"{token} is {item.disposition}, so {operation} is forbidden"
            )
        selected[item.address] = item
    return selected


def _state_json(tf_root: Path) -> dict[str, Any]:
    result = _run(("terraform", "state", "pull"), cwd=tf_root, capture=True)
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise BuildError("terraform state pull returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise BuildError("terraform state pull did not return an object")
    return value


def _terraform_version() -> None:
    result = _run(("terraform", "version", "-json"), capture=True)
    try:
        version = json.loads(result.stdout).get("terraform_version")
    except (json.JSONDecodeError, AttributeError) as exc:
        raise BuildError("terraform version returned invalid JSON") from exc
    if version != TERRAFORM_VERSION:
        raise BuildError(f"Terraform {TERRAFORM_VERSION} is required; found {version!r}")


def _source_guard(tf_root: Path) -> None:
    _run((sys.executable, str(BOUNDARY_SCRIPT), "--terraform-root", str(tf_root)))


def _account_guard(config: Mapping[str, Any]) -> None:
    result = _run(
        ("aws", "sts", "get-caller-identity", "--query", "Account", "--output", "text"),
        capture=True,
    )
    actual = result.stdout.strip()
    if actual != config["account_id"]:
        raise BuildError(
            f"wrong AWS account: expected {config['account_id']}, received {actual!r}"
        )


def _init_validate(config: Mapping[str, Any]) -> None:
    tf_root = config["tf_root"]
    _run(("terraform", "init", "-input=false", "-lockfile=readonly"), cwd=tf_root)
    _run(("terraform", "validate"), cwd=tf_root)
    sibling = config["sibling_root"]
    if sibling is not None:
        _run(("terraform", "init", "-input=false", "-lockfile=readonly"), cwd=sibling)


def _ownership_guard(environment: str, config: Mapping[str, Any]) -> None:
    args = [
        sys.executable,
        str(OWNERSHIP_SCRIPT),
        "--tf-root",
        str(config["tf_root"]),
        "--env",
        environment,
        "--region",
        config["region"],
    ]
    if config["sibling_root"] is not None:
        args.extend(("--sibling-tf-root", str(config["sibling_root"])))
    _run(args)


def _tagged_live_resources(environment: str, config: Mapping[str, Any]) -> list[str]:
    result = _run(
        (
            "aws",
            "resourcegroupstaggingapi",
            "get-resources",
            "--region",
            config["region"],
            "--tag-filters",
            "Key=Application,Values=uid-portal-api",
            f"Key=Environment,Values={environment}",
            "--query",
            "ResourceTagMappingList[].ResourceARN",
            "--output",
            "json",
        ),
        capture=True,
    )
    try:
        values = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise BuildError("resource tagging inventory returned invalid JSON") from exc
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise BuildError("resource tagging inventory returned an invalid ARN list")
    return sorted(set(values))


def _reviewed_state_owned_tagged_arns(
    live_arns: Sequence[str], config: Mapping[str, Any]
) -> set[str]:
    """Identify tagged network objects already handed to the State owner.

    A historical application state created some shared security groups and
    rules. ``removed { destroy = false }`` intentionally forgets them, but
    their old application tags remain visible to Resource Groups Tagging API.
    Ignore only exact manifest-listed groups and rules whose live parent group
    is manifest-listed; every other tagged ARN remains a planning blocker.
    """
    reviewed: set[str] = set()
    rule_arns: dict[str, str] = {}
    for arn in live_arns:
        if ":security-group/" in arn:
            group_id = arn.rsplit("/", 1)[-1]
            if _is_exact_protected("aws_security_group", {"id": group_id}):
                reviewed.add(arn)
        elif ":security-group-rule/" in arn:
            rule_id = arn.rsplit("/", 1)[-1]
            rule_arns[rule_id] = arn

    if not rule_arns:
        return reviewed

    result = _run(
        (
            "aws",
            "ec2",
            "describe-security-group-rules",
            "--region",
            config["region"],
            "--security-group-rule-ids",
            *sorted(rule_arns),
            "--output",
            "json",
        ),
        capture=True,
    )
    try:
        document = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise BuildError("security-group-rule inventory returned invalid JSON") from exc
    rules = document.get("SecurityGroupRules") if isinstance(document, Mapping) else None
    if not isinstance(rules, list) or any(not isinstance(rule, Mapping) for rule in rules):
        raise BuildError("security-group-rule inventory returned an invalid rule list")

    returned_ids: set[str] = set()
    for rule in rules:
        rule_id = rule.get("SecurityGroupRuleId")
        group_id = rule.get("GroupId")
        is_egress = rule.get("IsEgress")
        if (
            not isinstance(rule_id, str)
            or rule_id not in rule_arns
            or not isinstance(is_egress, bool)
        ):
            raise BuildError("security-group-rule inventory returned an unexpected rule")
        returned_ids.add(rule_id)
        if isinstance(group_id, str) and _is_exact_protected(
            (
                "aws_vpc_security_group_egress_rule"
                if is_egress
                else "aws_vpc_security_group_ingress_rule"
            ),
            {"security_group_id": group_id},
        ):
            reviewed.add(rule_arns[rule_id])

    if returned_ids != set(rule_arns):
        raise BuildError("security-group-rule inventory omitted a tagged live rule")
    return reviewed


def _untracked_tagged(instances: Sequence[Instance], live_arns: Sequence[str]) -> list[str]:
    tracked = set().union(*(item.arns for item in instances)) if instances else set()
    return [arn for arn in live_arns if arn not in tracked]


def _placeholder_lines(tf_root: Path) -> list[int]:
    return [
        number
        for number, line in enumerate(
            (tf_root / "terraform.tfvars").read_text(encoding="utf-8").splitlines(), 1
        )
        if "REPLACE_ME" in line and not line.lstrip().startswith("#")
    ]


def _preflight(environment: str, config: Mapping[str, Any]) -> tuple[list[Instance], str, int, list[str]]:
    _terraform_version()
    _source_guard(config["tf_root"])
    _account_guard(config)
    _init_validate(config)
    _ownership_guard(environment, config)
    instances, lineage, serial = parse_state(_state_json(config["tf_root"]))
    unknown = [item.display_address for item in instances if item.disposition == "blocker-unclassified"]
    if unknown:
        raise BuildError("unclassified Terraform resources block the build: " + ", ".join(unknown))
    live_arns = _tagged_live_resources(environment, config)
    reviewed_external_arns = _reviewed_state_owned_tagged_arns(live_arns, config)
    application_arns = [arn for arn in live_arns if arn not in reviewed_external_arns]
    return instances, lineage, serial, _untracked_tagged(instances, application_arns)


def _print_inventory(instances: Sequence[Instance], untracked: Sequence[str]) -> None:
    print("SELECTOR\tDISPOSITION\tTYPE\tSANITIZED_ADDRESS")
    for item in instances:
        selector = (
            item.selector
            if item.disposition in {"replaceable", "application-hold"}
            else "-"
        )
        print(f"{selector}\t{item.disposition}\t{item.resource_type}\t{item.display_address}")
    print(f"\nTagged live resources not represented by this Terraform state: {len(untracked)}")
    for arn in untracked:
        print(f"UNTRACKED\t{arn}")
    print(
        "LIMITATION: AWS tag inventory cannot prove absence of untagged resources. "
        "Untracked entries must be reconciled/imported by reviewed configuration; "
        "this tool never deletes them."
    )


def _planned_resources(
    module: Any, *, mode: str = "managed"
) -> Iterator[Mapping[str, Any]]:
    if not isinstance(module, Mapping):
        return
    for resource in module.get("resources", []):
        if isinstance(resource, Mapping) and resource.get("mode", "managed") == mode:
            yield resource
    for child in module.get("child_modules", []):
        yield from _planned_resources(child, mode=mode)


def _unknown_truthy(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, Mapping):
        return any(_unknown_truthy(child) for child in value.values())
    if isinstance(value, list):
        return any(_unknown_truthy(child) for child in value)
    return False


def _deferred_external_domain_is_guarded(
    plan: Mapping[str, Any],
    resource: Mapping[str, Any],
    config: Mapping[str, Any],
) -> bool:
    """Recognize Terraform's guarded apply-time external-domain read."""

    address = resource.get("address")
    values = resource.get("values")
    if not isinstance(address, str) or not isinstance(values, Mapping):
        return False
    expected_values = {
        "endpoint_configuration": [{"types": ["REGIONAL"]}],
        "security_policy": "TLS_1_2",
        "regional_certificate_arn": config["certificate_arn"],
    }
    changes = [
        item
        for item in plan.get("resource_changes", [])
        if isinstance(item, Mapping)
        and item.get("address") == address
        and item.get("mode") == "data"
        and item.get("type") == "aws_api_gateway_domain_name"
    ]
    if len(changes) != 1:
        return False
    change = changes[0].get("change")
    if not isinstance(change, Mapping) or change.get("actions") != ["read"]:
        return False
    after = change.get("after")
    after_unknown = change.get("after_unknown")
    if (
        not isinstance(after, Mapping)
        or after.get("domain_name") != config["domain_name"]
        or not isinstance(after_unknown, Mapping)
    ):
        return False
    for field, expected in expected_values.items():
        for known in (values, after):
            if field in known and known[field] != expected:
                return False
        if field not in values and not _unknown_truthy(after_unknown.get(field)):
            return False

    for check in plan.get("checks", []):
        if not isinstance(check, Mapping) or check.get("status") != "unknown":
            continue
        check_address = check.get("address")
        if not isinstance(check_address, Mapping) or check_address.get("mode") != "data":
            continue
        if check_address.get("type") != "aws_api_gateway_domain_name":
            continue
        instances = check.get("instances")
        if not isinstance(instances, list):
            continue
        if any(
            isinstance(instance, Mapping)
            and instance.get("status") == "unknown"
            and isinstance(instance.get("address"), Mapping)
            and instance["address"].get("to_display") == address
            for instance in instances
        ):
            return True
    return False


def validate_full_stack(plan: Mapping[str, Any], environment: str) -> None:
    planned = plan.get("planned_values")
    root = planned.get("root_module") if isinstance(planned, Mapping) else None
    resources = list(_planned_resources(root))
    data_resources = list(_planned_resources(root, mode="data"))
    counts: dict[str, int] = {}
    for resource in resources:
        resource_type = resource.get("type")
        if isinstance(resource_type, str):
            counts[resource_type] = counts.get(resource_type, 0) + 1
    config = ENVIRONMENTS[environment]
    expected_counts = {
        **EXPECTED_COUNTS,
        "aws_apigatewayv2_domain_name": (
            1 if config["domain_ownership"] == "managed" else 0
        ),
    }
    mismatches = {
        resource_type: (counts.get(resource_type, 0), expected)
        for resource_type, expected in expected_counts.items()
        if counts.get(resource_type, 0) != expected
    }
    if mismatches:
        raise BuildError(f"planned stack cardinality mismatch: {mismatches}")
    apis = [resource for resource in resources if resource.get("type") == "aws_apigatewayv2_api"]
    api_values = apis[0].get("values") if apis else None
    if not isinstance(api_values, Mapping):
        raise BuildError("planned API values are unavailable")
    if api_values.get("name") != config["api_name"] or api_values.get("disable_execute_api_endpoint") is not True:
        raise BuildError("planned API name/default-endpoint boundary is incorrect")
    domains = [
        resource
        for resource in resources
        if resource.get("type") == "aws_apigatewayv2_domain_name"
    ]
    external_domains = [
        resource
        for resource in data_resources
        if resource.get("type") == "aws_api_gateway_domain_name"
    ]
    if config["domain_ownership"] == "managed":
        domain_values = domains[0].get("values") if domains else None
        if (
            len(external_domains) != 0
            or not isinstance(domain_values, Mapping)
            or domain_values.get("domain_name") != config["domain_name"]
        ):
            raise BuildError("planned managed API custom-domain boundary is incorrect")
    else:
        domain_values = (
            external_domains[0].get("values") if len(external_domains) == 1 else None
        )
        configurations = (
            domain_values.get("endpoint_configuration")
            if isinstance(domain_values, Mapping)
            else None
        )
        configuration = (
            configurations[0]
            if isinstance(configurations, list) and len(configurations) == 1
            else None
        )
        known_contract_is_valid = (
            isinstance(configuration, Mapping)
            and configuration.get("types") == ["REGIONAL"]
            and isinstance(domain_values, Mapping)
            and domain_values.get("security_policy") == "TLS_1_2"
            and domain_values.get("regional_certificate_arn")
            == config["certificate_arn"]
        )
        deferred_contract_is_guarded = (
            len(external_domains) == 1
            and _deferred_external_domain_is_guarded(
                plan, external_domains[0], config
            )
        )
        if (
            domains
            or not isinstance(domain_values, Mapping)
            or domain_values.get("domain_name") != config["domain_name"]
            or not (known_contract_is_valid or deferred_contract_is_guarded)
        ):
            raise BuildError(
                "planned external API custom-domain read does not match the reviewed REGIONAL/TLS_1_2/certificate boundary"
            )
    mappings = [
        resource
        for resource in resources
        if resource.get("type") == "aws_apigatewayv2_api_mapping"
    ]
    mapping_values = mappings[0].get("values") if mappings else None
    if (
        not isinstance(mapping_values, Mapping)
        or mapping_values.get("api_mapping_key") not in (None, "")
    ):
        raise BuildError("planned API mapping must be the sole root mapping")
    stages = [
        resource
        for resource in resources
        if resource.get("type") == "aws_apigatewayv2_stage"
    ]
    stage_values = stages[0].get("values") if stages else None
    if (
        not isinstance(stage_values, Mapping)
        or stage_values.get("name") != "$default"
        or stage_values.get("auto_deploy") is not True
    ):
        raise BuildError(
            "planned API stage must be the sole auto-deployed $default stage"
        )
    functions = [resource for resource in resources if resource.get("type") == "aws_lambda_function"]
    for function in functions:
        values = function.get("values")
        if not isinstance(values, Mapping):
            raise BuildError("planned Lambda values are unavailable")
        name = values.get("function_name")
        vpc_config = values.get("vpc_config")
        if (
            not isinstance(name, str)
            or not name.startswith(config["lambda_prefix"])
            or values.get("runtime") != "python3.13"
            or not isinstance(vpc_config, list)
            or len(vpc_config) != 1
        ):
            raise BuildError(f"planned Lambda contract is incomplete at {function.get('address')}")


def validate_plan_identity(
    plan: Mapping[str, Any], environment: str, commit: str, build_time: str
) -> None:
    config = ENVIRONMENTS[environment]
    if plan.get("terraform_version") != TERRAFORM_VERSION:
        raise BuildError("saved plan was not created by the pinned Terraform version")
    variables = plan.get("variables")
    if not isinstance(variables, Mapping):
        raise BuildError("saved plan has no variables object")

    def planned_value(name: str) -> Any:
        item = variables.get(name)
        if not isinstance(item, Mapping) or "value" not in item:
            raise BuildError(f"saved plan does not expose required variable {name}")
        return item["value"]

    expected = {
        "aws_account_id": config["account_id"],
        "region": config["region"],
        "release_version": commit,
        "build_time": build_time,
        "offline_provider_validation": False,
    }
    for name, value in expected.items():
        if planned_value(name) != value:
            raise BuildError(f"saved plan variable {name} does not match this build")


def validate_selected_actions(
    plan: Mapping[str, Any], replacements: set[str], allowed_deletes: set[str]
) -> None:
    changes = plan.get("resource_changes")
    if not isinstance(changes, list):
        raise BuildError("plan has no resource_changes list")
    seen_replacements: set[str] = set()
    seen_deletes: set[str] = set()
    violations: list[str] = []
    for resource in changes:
        if not isinstance(resource, Mapping) or resource.get("mode", "managed") != "managed":
            continue
        address = resource.get("address")
        change = resource.get("change")
        actions = change.get("actions") if isinstance(change, Mapping) else None
        if not isinstance(address, str) or not isinstance(actions, list):
            raise BuildError("plan contains a malformed resource change")
        has_create = "create" in actions
        has_delete = "delete" in actions
        if has_create and has_delete:
            if address not in replacements:
                violations.append(f"unselected replacement: {address}")
            else:
                seen_replacements.add(address)
        elif has_delete:
            if address not in allowed_deletes:
                violations.append(f"unapproved delete: {address}")
            else:
                seen_deletes.add(address)
    for missing in sorted(replacements - seen_replacements):
        violations.append(f"selected replacement absent from plan: {missing}")
    for missing in sorted(allowed_deletes - seen_deletes):
        violations.append(f"allowed delete absent from plan: {missing}")
    if violations:
        raise BuildError("full-build destructive-action gate failed:\n  " + "\n  ".join(violations))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _source_digest(config: Mapping[str, Any]) -> str:
    roots = (
        config["tf_root"],
        INFRA_ROOT / "modules",
        REPO_ROOT / "services" / "api" / "routes" / "routes.yaml",
        INFRA_ROOT / "assets" / "layer-placeholder.zip",
        INFRA_ROOT / "assets" / "lambda-placeholder.zip",
        BOUNDARY_SCRIPT,
        OWNERSHIP_SCRIPT,
        MANIFEST,
        Path(__file__),
        SCRIPT_DIR / "full-build-tf-at.sh",
        SCRIPT_DIR / "full-build-tf-prod.sh",
    )
    files: set[Path] = set()
    for root in roots:
        if root.is_file():
            files.add(root)
        elif root.is_dir():
            files.update(
                path for path in root.rglob("*")
                if path.is_file()
                and ".terraform" not in path.parts
                and (path.suffix in {".tf", ".tfvars", ".json"})
            )
    digest = hashlib.sha256()
    for path in sorted(files):
        relative = str(path.relative_to(REPO_ROOT)).encode()
        data = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big") + relative)
        digest.update(len(data).to_bytes(8, "big") + data)
    return digest.hexdigest()


def _json_write(path: Path, value: Mapping[str, Any]) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def _render_plan(tf_root: Path, plan_file: Path) -> dict[str, Any]:
    result = _run(("terraform", "show", "-json", str(plan_file)), cwd=tf_root, capture=True)
    try:
        plan = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise BuildError("terraform show returned invalid plan JSON") from exc
    if not isinstance(plan, dict):
        raise BuildError("terraform show did not return an object")
    return plan


def _boundary_plan(config: Mapping[str, Any], plan: Mapping[str, Any]) -> None:
    _run(
        (
            sys.executable,
            str(BOUNDARY_SCRIPT),
            "--terraform-root",
            str(config["tf_root"]),
            "--plan-json",
            "-",
        ),
        input_text=json.dumps(plan, separators=(",", ":")),
    )


def _clean_commit() -> tuple[str, str]:
    status = _run(("git", "status", "--porcelain", "--untracked-files=normal"), capture=True)
    if status.stdout.strip():
        raise BuildError("full planning requires a clean committed worktree")
    commit = _run(("git", "rev-parse", "HEAD"), capture=True).stdout.strip()
    build_time = _run(("git", "show", "-s", "--format=%cI", "HEAD"), capture=True).stdout.strip()
    return commit, build_time


def _read_metadata(plan_file: Path) -> dict[str, Any]:
    path = Path(str(plan_file) + ".metadata.json")
    try:
        if path.stat().st_mode & 0o077:
            raise BuildError(f"plan metadata is not private mode 0600: {path}")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BuildError(f"cannot read valid plan metadata {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise BuildError("plan metadata must be an object")
    return value


def _create_plan_directory(environment: str) -> Path:
    plan_dir = Path(
        tempfile.mkdtemp(
            prefix=f"uid-full-build-{environment}-",
            dir=SCRIPT_DIR,
        )
    )
    os.chmod(plan_dir, 0o700)
    return plan_dir


def _verify_placeholder_packages() -> None:
    for path in (
        INFRA_ROOT / "assets" / "lambda-placeholder.zip",
        INFRA_ROOT / "assets" / "layer-placeholder.zip",
    ):
        if not path.is_file() or not zipfile.is_zipfile(path):
            raise BuildError(
                f"missing or invalid committed placeholder package: {path}; "
                f"run {SCRIPT_DIR / 'build-placeholder-packages.py'}"
            )


def _plan(environment: str, config: Mapping[str, Any], args: argparse.Namespace) -> None:
    commit, build_time = _clean_commit()
    placeholders = _placeholder_lines(config["tf_root"])
    if placeholders:
        raise BuildError(f"terraform.tfvars has unresolved placeholders on lines {placeholders}")
    _verify_placeholder_packages()
    instances, lineage, serial, untracked = _preflight(environment, config)
    if untracked:
        raise BuildError(
            "tagged live application resources are outside this state; rerun --dry-run "
            "and reconcile them before planning"
        )
    replacements = resolve_selectors(instances, args.delete_recreate, "replacement")
    allowed_deletes = resolve_selectors(instances, args.allow_delete, "deletion")
    overlap = set(replacements) & set(allowed_deletes)
    if overlap:
        raise BuildError("a resource cannot be both replaced and allowed for deletion")

    plan_dir = _create_plan_directory(environment)
    plan_file = plan_dir / "full-build.tfplan"
    plan_args = [
        "terraform",
        "plan",
        "-input=false",
        "-lock-timeout=5m",
        f"-out={plan_file}",
        f"-var=release_version={commit}",
        f"-var=build_time={build_time}",
    ]
    plan_args.extend(f"-replace={address}" for address in sorted(replacements))
    _run(plan_args, cwd=config["tf_root"])
    os.chmod(plan_file, 0o600)
    plan = _render_plan(config["tf_root"], plan_file)
    _boundary_plan(config, plan)
    validate_plan_identity(plan, environment, commit, build_time)
    validate_full_stack(plan, environment)
    validate_selected_actions(plan, set(replacements), set(allowed_deletes))
    sibling_state: dict[str, Any] | None = None
    if config["sibling_root"] is not None:
        sibling_state = _state_json(config["sibling_root"])
    now = datetime.now(timezone.utc)
    metadata = {
        "schema_version": 1,
        "environment": environment,
        "account_id": config["account_id"],
        "region": config["region"],
        "release_commit": commit,
        "build_time": build_time,
        "created_at": now.isoformat(),
        "expires_at": (now + PLAN_MAX_AGE).isoformat(),
        "plan_sha256": _sha256(plan_file),
        "plan_mtime_ns": plan_file.stat().st_mtime_ns,
        "source_sha256": _source_digest(config),
        "state_lineage": lineage,
        "state_serial": serial,
        "sibling_state_lineage": sibling_state.get("lineage") if sibling_state else None,
        "sibling_state_serial": sibling_state.get("serial") if sibling_state else None,
        "delete_recreate_addresses": sorted(replacements),
        "allowed_delete_addresses": sorted(allowed_deletes),
    }
    _json_write(Path(str(plan_file) + ".metadata.json"), metadata)
    text_path = Path(str(plan_file) + ".txt")
    text_result = _run(("terraform", "show", "-no-color", str(plan_file)), cwd=config["tf_root"], capture=True)
    descriptor = os.open(text_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text_result.stdout)
    print(f"PLAN={plan_file}")
    print(f"PLAN_SHA256={metadata['plan_sha256']}")
    print(f"REVIEW={text_path}")
    print("No apply was performed. Review the complete plan, then use --apply-plan PLAN.")


def _parse_time(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise BuildError(f"plan metadata {field} is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise BuildError(f"plan metadata {field} is invalid") from exc
    if parsed.tzinfo is None:
        raise BuildError(f"plan metadata {field} has no timezone")
    return parsed.astimezone(timezone.utc)


def _apply(environment: str, config: Mapping[str, Any], plan_file: Path) -> None:
    if not sys.stdin.isatty() or not sys.stdout.isatty() or os.environ.get("CI"):
        raise BuildError("saved plans may be applied only from an attended terminal")
    plan_file = plan_file.resolve(strict=True)
    if plan_file.stat().st_mode & 0o077:
        raise BuildError("saved plan is not private mode 0600")
    metadata = _read_metadata(plan_file)
    commit, build_time = _clean_commit()
    expected = {
        "schema_version": 1,
        "environment": environment,
        "account_id": config["account_id"],
        "region": config["region"],
        "release_commit": commit,
        "build_time": build_time,
        "plan_sha256": _sha256(plan_file),
        "plan_mtime_ns": plan_file.stat().st_mtime_ns,
        "source_sha256": _source_digest(config),
    }
    for field, value in expected.items():
        if metadata.get(field) != value:
            raise BuildError(f"saved plan metadata mismatch: {field}")
    now = datetime.now(timezone.utc)
    created = _parse_time(metadata.get("created_at"), "created_at")
    expires = _parse_time(metadata.get("expires_at"), "expires_at")
    if expires - created != PLAN_MAX_AGE or not (created <= now <= expires):
        raise BuildError("saved plan is outside its exact 30-minute review window")

    instances, lineage, serial, untracked = _preflight(environment, config)
    if untracked:
        raise BuildError("new tagged resources appeared after planning")
    if metadata.get("state_lineage") != lineage or metadata.get("state_serial") != serial:
        raise BuildError("target Terraform state changed after planning")
    if config["sibling_root"] is not None:
        sibling = _state_json(config["sibling_root"])
        if (
            metadata.get("sibling_state_lineage") != sibling.get("lineage")
            or metadata.get("sibling_state_serial") != sibling.get("serial")
        ):
            raise BuildError("sibling dev Terraform state changed after planning")
    raw_replacements = metadata.get("delete_recreate_addresses")
    raw_deletes = metadata.get("allowed_delete_addresses")
    if (
        not isinstance(raw_replacements, list)
        or not isinstance(raw_deletes, list)
        or not all(isinstance(value, str) for value in raw_replacements + raw_deletes)
        or len(raw_replacements) != len(set(raw_replacements))
        or len(raw_deletes) != len(set(raw_deletes))
    ):
        raise BuildError("saved plan metadata contains invalid resource addresses")
    replacements = set(raw_replacements)
    deletes = set(raw_deletes)
    eligible = {
        item.address
        for item in instances
        if item.disposition in {"replaceable", "application-hold"}
    }
    if not replacements.issubset(eligible) or not deletes.issubset(eligible):
        raise BuildError("a selected application resource is no longer eligible")
    plan = _render_plan(config["tf_root"], plan_file)
    _boundary_plan(config, plan)
    validate_plan_identity(plan, environment, commit, build_time)
    validate_full_stack(plan, environment)
    validate_selected_actions(plan, replacements, deletes)
    phrase = f"APPLY-{environment.upper()}-{metadata['plan_sha256'][:12]}"
    print(f"Type {phrase} to apply the exact reviewed plan:")
    if input().strip() != phrase:
        raise BuildError("confirmation phrase did not match; nothing was applied")
    _run(
        ("terraform", "apply", "-input=false", "-lock-timeout=5m", str(plan_file)),
        cwd=config["tf_root"],
    )
    api_id = _run(("terraform", "output", "-raw", "api_gateway_id"), cwd=config["tf_root"], capture=True).stdout.strip()
    api_name = _run(("terraform", "output", "-raw", "api_gateway_name"), cwd=config["tf_root"], capture=True).stdout.strip()
    vpc_json = _run(("terraform", "output", "-json", "lambda_vpc_config"), cwd=config["tf_root"], capture=True).stdout.strip()
    _run(
        (
            sys.executable,
            str(SCRIPT_DIR / "check-lambda-ingress.py"),
            "--env",
            environment,
            "--region",
            config["region"],
            "--api-id",
            api_id,
            "--api-name",
            api_name,
            "--allowed-host",
            config["allowed_host"],
            "--expected-vpc-config-json",
            vpc_json,
        )
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--environment", choices=sorted(ENVIRONMENTS), required=True, help=argparse.SUPPRESS)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--dry-run", action="store_true", help="read-only inventory; no plan or apply")
    modes.add_argument("--plan", action="store_true", help="validate placeholders and create a complete saved plan")
    modes.add_argument("--apply-plan", type=Path, metavar="PLAN", help="attended application of an exact plan created by this tool")
    parser.add_argument("--delete-recreate", action="append", default=[], metavar="SELECTOR", help="explicit dry-run selector to replace via Terraform -replace; repeatable")
    parser.add_argument("--allow-delete", action="append", default=[], metavar="SELECTOR", help="acknowledge one delete-only change already required by configuration; repeatable")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    config = ENVIRONMENTS[args.environment]
    try:
        if (args.delete_recreate or args.allow_delete) and not args.plan:
            raise BuildError("resource selectors are valid only with --plan")
        if args.dry_run:
            instances, _lineage, _serial, untracked = _preflight(args.environment, config)
            placeholders = _placeholder_lines(config["tf_root"])
            _print_inventory(instances, untracked)
            if placeholders:
                print(f"BLOCKED_FOR_PLAN: terraform.tfvars placeholder lines {placeholders}")
        elif args.plan:
            _plan(args.environment, config, args)
        else:
            _apply(args.environment, config, args.apply_plan)
    except (BuildError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
