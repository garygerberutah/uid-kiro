#!/usr/bin/env python3
"""Audit an AT application teardown without exposing state values.

This command never invokes AWS or changes Terraform state. It invokes only the
pinned Terraform CLI's read-only ``version`` and ``show -json`` commands and
fails closed around three boundaries:

* State inventory prints only root metadata, Terraform addresses, types and a
  disposition.  It never prints ids, attributes, outputs or provider data.
* A configuration-driven teardown plan may delete only the exact disposable
  application instances already present in the supplied AT state.  Shared
  State of Utah infrastructure may only be left alone or forgotten with a
  ``removed { destroy = false }`` handoff.
* A short-lived attestation binds the reviewed saved-plan bytes to the state
  lineage/serial and relevant Terraform sources.  The pre-apply verification
  refuses a changed plan, changed state, changed source tree or expired review.

There is deliberately no ``terraform destroy``, ``-target`` or apply wrapper
here.  A teardown must be expressed in reviewed Terraform configuration so the
normal dependency graph remains intact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


INFRA_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[6]
AT_TERRAFORM_ROOT = INFRA_ROOT / "envs" / "at"
STATE_OWNED_BOUNDARY_SCRIPT = INFRA_ROOT / "scripts" / "check-state-owned-boundary.py"
AT_ACCOUNT_ID = "705157108110"
AT_REGION = "us-west-2"
AT_ADDRESS_PREFIX = "module.stack."
STABLE_API_ADDRESS = "module.stack.module.portal_api.aws_apigatewayv2_api.this"
STABLE_GATEWAY_ADDRESSES = {
    "aws_apigatewayv2_api": STABLE_API_ADDRESS,
    "aws_apigatewayv2_domain_name": (
        "module.stack.module.portal_api.aws_apigatewayv2_domain_name.this[0]"
    ),
    "aws_apigatewayv2_api_mapping": (
        "module.stack.module.portal_api.aws_apigatewayv2_api_mapping.this[0]"
    ),
}
API_ID = re.compile(r"^[a-z0-9]{10}$")
ATTESTATION_VERSION = 2
DEFAULT_MAX_AGE_MINUTES = 30
PINNED_TERRAFORM_VERSION = "1.15.8"

# These are stateless application instances whose service-side objects can be
# reconstructed from the current configuration and placeholder packages. A
# rebuilt Lambda still needs the separate software workflow before cutover. The
# allowlist is intentionally exact; a newly introduced Terraform type becomes
# a blocker until its deletion semantics have been reviewed.
REBUILDABLE_TYPES = frozenset(
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

# These objects are application-owned, but deleting them is not part of the
# first teardown pass.  The sole API needs a separately reviewed lifecycle
# transition; edge bindings, queues, notifications and logs hold continuity or
# operational evidence.  The separate RDS Proxy state is held as an entire
# root and is never passed to check-plan.
APPLICATION_HOLD_TYPES = frozenset(
    {
        "aws_apigatewayv2_api",
        "aws_apigatewayv2_api_mapping",
        "aws_apigatewayv2_domain_name",
        "aws_cloudwatch_log_group",
        "aws_sns_topic",
        "aws_sns_topic_subscription",
        "aws_sqs_queue",
    }
)

# State-owned/durable infrastructure is immutable to this repository.  Prefix
# matching is deliberate here: a provider adding a more specific resource in
# one of these families must still fail closed rather than slip through an
# incomplete exact list.
STATE_OWNED_PREFIXES = (
    "aws_acm_",
    "aws_cloudfront_",
    "aws_db_",
    "aws_dynamodb_",
    "aws_ec2_",
    "aws_elasticache_",
    "aws_glue_",
    "aws_internet_gateway",
    "aws_kms_",
    "aws_lb",
    "aws_nat_gateway",
    "aws_network",
    "aws_rds_",
    "aws_redshift_",
    "aws_route",
    "aws_route53_",
    "aws_s3_",
    "aws_secretsmanager_",
    "aws_security_group",
    "aws_subnet",
    "aws_vpc",
    "aws_vpn_",
    "postgresql_",
)

SAFE_NO_MUTATION_ACTIONS = frozenset({("no-op",), ("read",)})
SAFE_STATE_HANDOFF_ACTION = ("forget",)


class AuditError(RuntimeError):
    """The requested proof could not be established."""


@dataclass(frozen=True)
class StateInstance:
    address: str
    display_address: str
    resource_type: str
    mode: str
    disposition: str


@dataclass(frozen=True)
class StateDocument:
    label: str
    path: Path
    lineage: str
    serial: int
    instances: tuple[StateInstance, ...]


def _load_json(path: Path, description: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise AuditError(f"cannot read {description} {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise AuditError(f"{description} {path} is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise AuditError(f"{description} {path} must contain a JSON object")
    return value


def _terraform_binary(value: str) -> Path:
    resolved = shutil.which(value)
    if resolved is None:
        raise AuditError(f"cannot find Terraform binary {value!r}")
    return Path(resolved).resolve()


def _run_read_only(args: Sequence[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            list(args),
            # `terraform show -json` loads the initialized provider schemas.
            # Running at the AT root binds those schemas to this exact plan,
            # rather than whatever Terraform directory the operator happens
            # to have as the shell's current working directory.
            cwd=AT_TERRAFORM_ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AuditError(f"cannot execute read-only command {args[0]}: {exc}") from exc


def _render_saved_plan(plan_file: Path, terraform_bin: str) -> tuple[dict[str, Any], Path]:
    binary = _terraform_binary(terraform_bin)
    try:
        plan_file = plan_file.resolve(strict=True)
    except OSError as exc:
        raise AuditError(f"cannot resolve saved plan {plan_file}: {exc}") from exc
    version_result = _run_read_only((str(binary), "version", "-json"))
    if version_result.returncode != 0:
        detail = (version_result.stderr or version_result.stdout).strip()
        raise AuditError(f"terraform version failed: {detail or version_result.returncode}")
    try:
        version = json.loads(version_result.stdout).get("terraform_version")
    except (json.JSONDecodeError, AttributeError) as exc:
        raise AuditError("terraform version -json returned invalid JSON") from exc
    if version != PINNED_TERRAFORM_VERSION:
        raise AuditError(
            f"Terraform {PINNED_TERRAFORM_VERSION} is required to inspect the saved plan; "
            f"found {version!r}"
        )

    show_result = _run_read_only((str(binary), "show", "-json", str(plan_file)))
    if show_result.returncode != 0:
        detail = (show_result.stderr or show_result.stdout).strip()
        raise AuditError(f"terraform show -json failed: {detail or show_result.returncode}")
    try:
        plan = json.loads(show_result.stdout)
    except json.JSONDecodeError as exc:
        raise AuditError("terraform show -json returned invalid plan JSON") from exc
    if not isinstance(plan, dict):
        raise AuditError("terraform show -json did not return a JSON object")
    if plan.get("terraform_version") != PINNED_TERRAFORM_VERSION:
        raise AuditError("saved plan reports a different Terraform version")
    return plan, binary


def _validate_repository_boundary(plan: Mapping[str, Any]) -> None:
    """Run the canonical source/plan boundary on the exact rendered plan.

    Keeping this inside the attestation primitive means an operator cannot get
    a rebuild PASS merely by omitting the separate runbook command. The plan is
    sent over stdin and is never written to another file.
    """

    if not STATE_OWNED_BOUNDARY_SCRIPT.is_file():
        raise AuditError(
            f"State-owned boundary checker is missing: {STATE_OWNED_BOUNDARY_SCRIPT}"
        )
    try:
        result = subprocess.run(
            (
                sys.executable,
                str(STATE_OWNED_BOUNDARY_SCRIPT),
                "--terraform-root",
                str(AT_TERRAFORM_ROOT),
                "--plan-json",
                "-",
            ),
            cwd=REPO_ROOT,
            input=json.dumps(plan, separators=(",", ":")),
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AuditError(f"cannot run State-owned boundary checker: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise AuditError(
            "exact saved plan failed the repository State-owned source/plan "
            f"boundary: {detail or f'exit {result.returncode}'}"
        )


def _index_suffix(index_key: Any, *, sanitized: bool = False) -> str:
    if index_key is None:
        return ""
    if sanitized and isinstance(index_key, str):
        digest = hashlib.sha256(index_key.encode("utf-8")).hexdigest()[:16]
        index_key = f"sha256:{digest}"
    return f"[{json.dumps(index_key, ensure_ascii=True, separators=(',', ':'))}]"


def _disposition(resource_type: str, address: str, root_label: str) -> str:
    if root_label == "db-proxy-dev":
        return "hold-separate-root"
    if (
        resource_type.startswith("aws_s3_")
        and ".module.storage." in address
        and address.endswith('["artifacts"]')
    ):
        # The report-artifact bucket is UID application-owned, unlike adopted
        # SIFE storage, but still durable and excluded from the first teardown.
        return "application-hold"
    if resource_type.startswith(STATE_OWNED_PREFIXES):
        return "state-owned"
    if resource_type in APPLICATION_HOLD_TYPES:
        return "application-hold"
    if (
        root_label == "at"
        and address.startswith(AT_ADDRESS_PREFIX)
        and resource_type in REBUILDABLE_TYPES
    ):
        return "rebuildable"
    return "blocker-unclassified"


def _parse_state(label: str, path: Path) -> StateDocument:
    raw = _load_json(path, "Terraform state")
    lineage = raw.get("lineage")
    serial = raw.get("serial")
    resources = raw.get("resources")
    if not isinstance(lineage, str) or not lineage:
        raise AuditError(f"Terraform state {path} has no nonempty lineage")
    if not isinstance(serial, int) or serial < 0:
        raise AuditError(f"Terraform state {path} has no valid serial")
    if not isinstance(resources, list):
        raise AuditError(f"Terraform state {path} has no resources list")

    instances: list[StateInstance] = []
    seen: set[str] = set()
    for resource in resources:
        if not isinstance(resource, Mapping):
            raise AuditError(f"Terraform state {path} has a malformed resource")
        mode = resource.get("mode", "managed")
        resource_type = resource.get("type")
        name = resource.get("name")
        module = resource.get("module", "")
        raw_instances = resource.get("instances")
        if mode not in {"managed", "data"}:
            raise AuditError(f"Terraform state {path} has unsupported mode {mode!r}")
        if not isinstance(resource_type, str) or not isinstance(name, str):
            raise AuditError(f"Terraform state {path} has a resource without type/name")
        if not isinstance(module, str) or not isinstance(raw_instances, list):
            raise AuditError(f"Terraform state {path} has malformed {resource_type}.{name}")
        base = ".".join(part for part in (module, f"{resource_type}.{name}") if part)
        for instance in raw_instances:
            if not isinstance(instance, Mapping):
                raise AuditError(f"Terraform state {path} has a malformed instance")
            if instance.get("deposed") not in {None, ""}:
                raise AuditError(f"{base} has a deposed instance; reconcile it first")
            if instance.get("status") == "tainted":
                raise AuditError(f"{base} is tainted; reconcile it before teardown")
            address = base + _index_suffix(instance.get("index_key"))
            display_address = base + _index_suffix(
                instance.get("index_key"), sanitized=True
            )
            if address in seen:
                raise AuditError(f"Terraform state {path} repeats address {address}")
            seen.add(address)
            if mode == "managed" and resource_type == "aws_apigatewayv2_api":
                attributes = instance.get("attributes")
                api_id = attributes.get("id") if isinstance(attributes, Mapping) else None
                if not isinstance(api_id, str) or not API_ID.fullmatch(api_id):
                    raise AuditError(
                        f"{display_address} has no valid ten-character API id; "
                        "the id is intentionally not printed"
                    )
            disposition = (
                "data-read"
                if mode == "data"
                else _disposition(resource_type, address, label)
            )
            instances.append(
                StateInstance(
                    address,
                    display_address,
                    resource_type,
                    mode,
                    disposition,
                )
            )

    return StateDocument(label, path, lineage, serial, tuple(sorted(instances, key=lambda x: x.address)))


def _validate_gateway_state(at_state: StateDocument, dev_state: StateDocument) -> None:
    if at_state.label != "at" or dev_state.label != "dev":
        raise AuditError("gateway ownership proof requires at and dev states")
    if at_state.lineage == dev_state.lineage:
        raise AuditError("AT and sibling dev states must have distinct lineages")
    dev_gateway_resources = [
        instance
        for instance in dev_state.instances
        if instance.mode == "managed"
        and instance.resource_type in STABLE_GATEWAY_ADDRESSES
    ]
    if dev_gateway_resources:
        addresses = ", ".join(
            instance.display_address for instance in dev_gateway_resources
        )
        raise AuditError(
            "sibling dev state must own zero API Gateway v2 APIs, custom "
            f"domains or mappings before an AT rebuild ({addresses})"
        )

    for resource_type, stable_address in STABLE_GATEWAY_ADDRESSES.items():
        instances = [
            instance
            for instance in at_state.instances
            if instance.mode == "managed"
            and instance.resource_type == resource_type
        ]
        if len(instances) > 1:
            raise AuditError(
                f"AT state owns more than one {resource_type} resource"
            )
        if instances and instances[0].address != stable_address:
            raise AuditError(
                "AT API Gateway v2 state must use only the stable survivor "
                f"address {stable_address}; found {instances[0].display_address}"
            )


def _parse_state_arg(value: str) -> tuple[str, Path]:
    label, separator, raw_path = value.partition("=")
    if not separator or not label or not raw_path:
        raise argparse.ArgumentTypeError("state must be LABEL=PATH")
    if label not in {"at", "dev", "db-proxy-dev"}:
        raise argparse.ArgumentTypeError(
            "state label must be at, dev, or db-proxy-dev"
        )
    return label, Path(raw_path)


def _inventory_payload(states: Sequence[StateDocument]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "sanitized": True,
        "roots": [
            {
                "label": state.label,
                "lineage": state.lineage,
                "serial": state.serial,
                "managed_count": sum(i.mode == "managed" for i in state.instances),
                "data_count": sum(i.mode == "data" for i in state.instances),
                "resources": [
                    {
                        "address": instance.display_address,
                        "type": instance.resource_type,
                        "disposition": instance.disposition,
                    }
                    for instance in state.instances
                    if instance.mode == "managed"
                ],
            }
            for state in states
        ],
    }


def _write_private_json(path: Path, value: Mapping[str, Any]) -> None:
    encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
    except OSError as exc:
        raise AuditError(f"cannot write {path}: {exc}") from exc


def _managed_plan_prior_state(plan: Mapping[str, Any]) -> dict[str, str]:
    prior_state = plan.get("prior_state")
    if not isinstance(prior_state, Mapping):
        raise AuditError("plan JSON has no prior_state object")
    values = prior_state.get("values")
    if not isinstance(values, Mapping):
        raise AuditError("plan JSON prior_state has no values object")
    root = values.get("root_module")
    if not isinstance(root, Mapping):
        raise AuditError("plan JSON prior_state has no root_module")

    found: dict[str, str] = {}

    def visit(module: Mapping[str, Any]) -> None:
        resources = module.get("resources", [])
        children = module.get("child_modules", [])
        if not isinstance(resources, list) or not isinstance(children, list):
            raise AuditError("plan JSON prior_state module is malformed")
        for resource in resources:
            if not isinstance(resource, Mapping):
                raise AuditError("plan JSON prior_state resource is malformed")
            if resource.get("mode", "managed") != "managed":
                continue
            address = resource.get("address")
            resource_type = resource.get("type")
            if not isinstance(address, str) or not isinstance(resource_type, str):
                raise AuditError("plan JSON prior_state resource lacks address/type")
            if address in found:
                raise AuditError(f"plan JSON prior_state repeats {address}")
            found[address] = resource_type
        for child in children:
            if not isinstance(child, Mapping):
                raise AuditError("plan JSON prior_state child module is malformed")
            visit(child)

    visit(root)
    return found


def _state_managed_map(state: StateDocument) -> dict[str, str]:
    return {
        instance.address: instance.resource_type
        for instance in state.instances
        if instance.mode == "managed"
    }


def _plan_identity(plan: Mapping[str, Any]) -> None:
    variables = plan.get("variables")
    if not isinstance(variables, Mapping):
        raise AuditError("plan JSON has no variables object")

    def value(name: str) -> Any:
        item = variables.get(name)
        if not isinstance(item, Mapping) or "value" not in item:
            raise AuditError(f"plan JSON does not expose required variable {name}")
        return item["value"]

    if str(value("aws_account_id")) != AT_ACCOUNT_ID:
        raise AuditError(f"plan is not for AT account {AT_ACCOUNT_ID}")
    if str(value("region")) != AT_REGION:
        raise AuditError(f"plan is not for AT region {AT_REGION}")
    if value("offline_provider_validation") is not False:
        raise AuditError("offline_provider_validation must be false in a teardown plan")


def _plan_deletions(plan: Mapping[str, Any], state: StateDocument) -> list[str]:
    if state.label != "at":
        raise AuditError("check-plan accepts only an at=... state")

    # Terraform 1.15 can represent provider actions and work postponed until a
    # later apply outside resource_changes. Those paths are intentionally not
    # allowlisted: an action can invoke Lambda or invalidate CloudFront without
    # changing a managed resource, and a deferred change has not yet exposed
    # complete semantics for review.
    required_status = {
        "complete": True,
        "applyable": True,
        "errored": False,
    }
    for field, expected in required_status.items():
        if plan.get(field) is not expected:
            raise AuditError(
                f"saved teardown plan must have {field}={str(expected).lower()}"
            )
    for field in (
        "action_invocations",
        "deferred_action_invocations",
        "deferred_changes",
    ):
        value = plan.get(field, [])
        if not isinstance(value, list):
            raise AuditError(f"saved teardown plan has malformed {field}")
        if value:
            raise AuditError(
                f"saved teardown plan contains forbidden {field}; "
                "provider actions and deferred work cannot be attested"
            )

    expected_prior = _state_managed_map(state)
    actual_prior = _managed_plan_prior_state(plan)
    if actual_prior != expected_prior:
        missing = sorted(set(expected_prior) - set(actual_prior))
        extra = sorted(set(actual_prior) - set(expected_prior))
        mismatched = sorted(
            address
            for address in set(expected_prior) & set(actual_prior)
            if expected_prior[address] != actual_prior[address]
        )
        raise AuditError(
            "saved plan prior state does not match the freshly pulled AT state "
            f"(missing={missing}, extra={extra}, type_mismatch={mismatched})"
        )

    _plan_identity(plan)
    changes = plan.get("resource_changes")
    if not isinstance(changes, list):
        raise AuditError("plan JSON has no resource_changes list")

    by_address = {
        instance.address: instance
        for instance in state.instances
        if instance.mode == "managed"
    }
    expected_deletions = {
        address
        for address, instance in by_address.items()
        if instance.disposition == "rebuildable"
    }
    blockers = sorted(
        address
        for address, instance in by_address.items()
        if instance.disposition == "blocker-unclassified"
    )
    if blockers:
        raise AuditError(
            "AT state contains unclassified managed resources: " + ", ".join(blockers)
        )

    actual_deletions: set[str] = set()
    violations: list[str] = []
    for resource in changes:
        if not isinstance(resource, Mapping):
            raise AuditError("plan resource_changes entry is malformed")
        if resource.get("mode", "managed") == "data":
            continue
        address = resource.get("address")
        resource_type = resource.get("type")
        change = resource.get("change")
        if not isinstance(address, str) or not isinstance(resource_type, str):
            raise AuditError("plan resource change lacks address/type")
        if not isinstance(change, Mapping):
            raise AuditError(f"plan resource change {address} has no change object")
        raw_actions = change.get("actions")
        if not isinstance(raw_actions, list) or not raw_actions or not all(
            isinstance(action, str) for action in raw_actions
        ):
            raise AuditError(f"plan resource change {address} has invalid actions")
        actions = tuple(raw_actions)
        importing = change.get("importing") is not None
        instance = by_address.get(address)
        if instance is None:
            if actions not in SAFE_NO_MUTATION_ACTIONS:
                violations.append(f"{address}\t{resource_type}\t{','.join(actions)}\tnot-in-state")
            continue
        if resource_type != instance.resource_type:
            violations.append(f"{address}\t{resource_type}\ttype-mismatch")
            continue
        if importing:
            violations.append(f"{address}\t{resource_type}\timport")
            continue
        if instance.disposition == "rebuildable" and actions == ("delete",):
            actual_deletions.add(address)
        elif (
            instance.disposition == "state-owned"
            and actions == SAFE_STATE_HANDOFF_ACTION
        ):
            # Safe relinquishment only: the resource continues to exist.
            continue
        elif actions not in SAFE_NO_MUTATION_ACTIONS:
            violations.append(
                f"{address}\t{resource_type}\t{','.join(actions)}\t{instance.disposition}"
            )

    missing_deletions = sorted(expected_deletions - actual_deletions)
    extra_deletions = sorted(actual_deletions - expected_deletions)
    if missing_deletions:
        violations.append("missing exact rebuild deletions: " + ", ".join(missing_deletions))
    if extra_deletions:
        violations.append("unexpected rebuild deletions: " + ", ".join(extra_deletions))
    if not expected_deletions:
        violations.append("AT state contains no classified rebuildable resources")
    if violations:
        raise AuditError("teardown plan violates the rebuild boundary:\n  " + "\n  ".join(violations))
    return sorted(actual_deletions)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise AuditError(f"cannot hash {path}: {exc}") from exc
    return digest.hexdigest()


def _source_files(repo_root: Path) -> Iterable[Path]:
    roots = (
        repo_root / "aws" / "terraform" / "repos" / "utahdts" / "uid-portal" / "envs" / "at",
        repo_root / "aws" / "terraform" / "repos" / "utahdts" / "uid-portal" / "modules",
    )
    for root in roots:
        if not root.is_dir():
            raise AuditError(f"required Terraform source root is missing: {root}")
        for path in sorted(root.rglob("*")):
            if path.is_file() and ".terraform" not in path.parts and path.suffix in {".tf", ".tfvars"}:
                yield path
    for relative in (
        "aws/terraform/repos/utahdts/uid-portal/state-owned-resources.json",
        "services/api/routes/routes.yaml",
        "aws/terraform/repos/utahdts/uid-portal/scripts/check-at-rebuild.py",
        "aws/terraform/repos/utahdts/uid-portal/scripts/check-state-owned-boundary.py",
    ):
        path = repo_root / relative
        if path.is_file():
            yield path


def _source_digest(repo_root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(set(_source_files(repo_root))):
        relative = path.relative_to(repo_root).as_posix().encode()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        data = path.read_bytes()
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _make_attestation(
    plan_file: Path,
    state: StateDocument,
    dev_state: StateDocument,
    repo_root: Path,
    deletions: Sequence[str],
    terraform_binary: Path,
) -> dict[str, Any]:
    now = _utc_now()
    plan_modified = datetime.fromtimestamp(plan_file.stat().st_mtime, timezone.utc)
    if plan_modified > now + timedelta(minutes=5):
        raise AuditError("saved plan modification time is in the future")
    if now - plan_modified > timedelta(minutes=DEFAULT_MAX_AGE_MINUTES):
        raise AuditError("stale saved plan: file is older than the 30-minute review window")
    return {
        "schema_version": ATTESTATION_VERSION,
        "environment": "at",
        "account_id": AT_ACCOUNT_ID,
        "region": AT_REGION,
        "plan_sha256": _sha256(plan_file),
        "plan_mtime_ns": plan_file.stat().st_mtime_ns,
        "state_lineage": state.lineage,
        "state_serial": state.serial,
        "dev_state_lineage": dev_state.lineage,
        "dev_state_serial": dev_state.serial,
        "source_sha256": _source_digest(repo_root),
        "terraform_binary": str(terraform_binary),
        "terraform_version": PINNED_TERRAFORM_VERSION,
        "validated_deletions": list(deletions),
        # Derive the window from filesystem metadata that verify checks again;
        # do not let editable receipt timestamps extend the review.
        "created_at": plan_modified.isoformat(),
        "expires_at": (
            plan_modified + timedelta(minutes=DEFAULT_MAX_AGE_MINUTES)
        ).isoformat(),
    }


def _parse_time(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise AuditError(f"attestation {field} is not a timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise AuditError(f"attestation {field} is invalid") from exc
    if parsed.tzinfo is None:
        raise AuditError(f"attestation {field} has no timezone")
    return parsed.astimezone(timezone.utc)


def _verify_attestation(
    attestation: Mapping[str, Any],
    plan_file: Path,
    state: StateDocument,
    dev_state: StateDocument,
    repo_root: Path,
    deletions: Sequence[str],
    terraform_binary: Path,
) -> None:
    if attestation.get("schema_version") != ATTESTATION_VERSION:
        raise AuditError("attestation schema version is unsupported")
    expected_static = {
        "environment": "at",
        "account_id": AT_ACCOUNT_ID,
        "region": AT_REGION,
        "state_lineage": state.lineage,
        "state_serial": state.serial,
        "dev_state_lineage": dev_state.lineage,
        "dev_state_serial": dev_state.serial,
        "plan_sha256": _sha256(plan_file),
        "plan_mtime_ns": plan_file.stat().st_mtime_ns,
        "source_sha256": _source_digest(repo_root),
        "terraform_binary": str(terraform_binary),
        "terraform_version": PINNED_TERRAFORM_VERSION,
        "validated_deletions": list(deletions),
    }
    for field, expected in expected_static.items():
        if attestation.get(field) != expected:
            raise AuditError(f"stale attestation: {field} changed")
    created = _parse_time(attestation.get("created_at"), "created_at")
    expires = _parse_time(attestation.get("expires_at"), "expires_at")
    now = _utc_now()
    if expires <= created:
        raise AuditError("attestation expiry is not after its creation")
    if expires - created != timedelta(minutes=DEFAULT_MAX_AGE_MINUTES):
        raise AuditError("attestation review window is not exactly 30 minutes")
    if created > now + timedelta(minutes=5):
        raise AuditError("attestation creation time is in the future")
    if now > expires:
        raise AuditError("stale attestation: review window expired")
    plan_modified = datetime.fromtimestamp(plan_file.stat().st_mtime, timezone.utc)
    if created != plan_modified:
        raise AuditError("stale attestation: creation time does not match plan mtime")
    if plan_modified > now + timedelta(minutes=5):
        raise AuditError("saved plan modification time is in the future")
    if now - plan_modified > timedelta(minutes=DEFAULT_MAX_AGE_MINUTES):
        raise AuditError("stale saved plan: file is older than the 30-minute review window")
    # The semantic deletion set above was freshly rendered from the exact
    # saved-plan bytes. The attestation is a review receipt, not a trusted
    # substitute for re-running that validation.


def _repo_root(value: str) -> Path:
    resolved = Path(value).resolve()
    if resolved != REPO_ROOT.resolve():
        raise argparse.ArgumentTypeError(
            f"repo root must resolve to this checkout: {REPO_ROOT}"
        )
    return resolved


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    inventory = subparsers.add_parser("inventory", help="print a sanitized state inventory")
    inventory.add_argument("--state", action="append", type=_parse_state_arg, required=True)
    inventory.add_argument("--output", type=Path, help="optional private sanitized JSON output")

    check = subparsers.add_parser("check-plan", help="validate and attest a saved teardown plan")
    check.add_argument("--plan-file", type=Path, required=True)
    check.add_argument("--state", type=Path, required=True)
    check.add_argument("--dev-state", type=Path, required=True)
    check.add_argument("--attestation", type=Path, required=True)
    check.add_argument("--repo-root", type=_repo_root, default=REPO_ROOT)
    check.add_argument("--terraform-bin", default="terraform")

    verify = subparsers.add_parser("verify-attestation", help="refuse a stale reviewed plan")
    verify.add_argument("--plan-file", type=Path, required=True)
    verify.add_argument("--current-state", type=Path, required=True)
    verify.add_argument("--current-dev-state", type=Path, required=True)
    verify.add_argument("--attestation", type=Path, required=True)
    verify.add_argument("--repo-root", type=_repo_root, default=REPO_ROOT)
    verify.add_argument("--terraform-bin", default="terraform")
    return parser


def _inventory_command(args: argparse.Namespace) -> None:
    labels = [label for label, _path in args.state]
    if len(set(labels)) != len(labels):
        raise AuditError("each state label may be supplied only once")
    required_labels = {"at", "dev", "db-proxy-dev"}
    if set(labels) != required_labels:
        missing = sorted(required_labels - set(labels))
        extra = sorted(set(labels) - required_labels)
        raise AuditError(
            "inventory requires all known shared-account roots "
            f"(missing={missing}, extra={extra})"
        )
    states = [_parse_state(label, path) for label, path in args.state]
    lineages = [state.lineage for state in states]
    if len(set(lineages)) != len(lineages):
        raise AuditError("two supplied state roots have the same lineage")
    states_by_label = {state.label: state for state in states}
    _validate_gateway_state(states_by_label["at"], states_by_label["dev"])
    payload = _inventory_payload(states)
    encoded = json.dumps(payload, indent=2, sort_keys=True)
    print(encoded)
    if args.output:
        _write_private_json(args.output, payload)


def _check_command(args: argparse.Namespace) -> None:
    state = _parse_state("at", args.state)
    dev_state = _parse_state("dev", args.dev_state)
    _validate_gateway_state(state, dev_state)
    plan, terraform_binary = _render_saved_plan(args.plan_file, args.terraform_bin)
    deletions = _plan_deletions(plan, state)
    _validate_repository_boundary(plan)
    attestation = _make_attestation(
        args.plan_file,
        state,
        dev_state,
        args.repo_root,
        deletions,
        terraform_binary,
    )
    _write_private_json(args.attestation, attestation)
    print(
        f"PASS: exact AT rebuild plan validated; {len(deletions)} disposable "
        f"application instances; attestation expires at {attestation['expires_at']}"
    )


def _verify_command(args: argparse.Namespace) -> None:
    state = _parse_state("at", args.current_state)
    dev_state = _parse_state("dev", args.current_dev_state)
    _validate_gateway_state(state, dev_state)
    attestation = _load_json(args.attestation, "rebuild attestation")
    plan, terraform_binary = _render_saved_plan(args.plan_file, args.terraform_bin)
    deletions = _plan_deletions(plan, state)
    _validate_repository_boundary(plan)
    _verify_attestation(
        attestation,
        args.plan_file,
        state,
        dev_state,
        args.repo_root,
        deletions,
        terraform_binary,
    )
    print(
        "PASS: saved plan, AT/dev state lineages/serials, Terraform sources and "
        "review window still match; no apply was performed"
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "inventory":
            _inventory_command(args)
        elif args.command == "check-plan":
            _check_command(args)
        elif args.command == "verify-attestation":
            _verify_command(args)
        else:  # pragma: no cover - argparse enforces this
            raise AuditError(f"unsupported command {args.command}")
    except AuditError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
