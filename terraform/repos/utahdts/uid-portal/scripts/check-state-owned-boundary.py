#!/usr/bin/env python3
"""Enforce read-only use of every State of Utah-owned resource.

This checker has two complementary inputs:

* ``--terraform-root`` audits declarations and follows local module sources.
  It blocks protected resource families and ways to hide provisioning.
* ``--plan-json`` audits the exact saved plan. A managed network resource may
  only use Terraform's non-destructive ``forget`` transition; the same applies
  to exact external resources in the versioned ownership manifest. Data reads
  remain permitted.

The source audit intentionally has no third-party parser dependency so it can
run before ``terraform init``. Native ``.tf.json`` is parsed structurally;
HCL ``.tf`` declarations are lexed after comments and heredocs are masked.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator


# AWS provider resources that own shared-network topology or policy. Prefixes
# are only used where the namespace is network-specific. In particular, never
# use ``awscc_ec2_`` here: it also matches instances, volumes, key pairs, etc.
NETWORK_RESOURCE_TYPES = frozenset(
    {
        "aws_alb",
        "aws_apigatewayv2_vpc_link",
        "aws_customer_gateway",
        "aws_default_network_acl",
        "aws_default_route_table",
        "aws_default_security_group",
        "aws_default_subnet",
        "aws_default_vpc",
        "aws_default_vpc_dhcp_options",
        "aws_ec2_tag",
        "aws_ec2_subnet_cidr_reservation",
        "aws_egress_only_internet_gateway",
        "aws_eip",
        "aws_eip_association",
        "aws_elb",
        "aws_flow_log",
        "aws_internet_gateway",
        "aws_internet_gateway_attachment",
        "aws_lb",
        "aws_main_route_table_association",
        "aws_nat_gateway",
        "aws_network_acl",
        "aws_network_acl_association",
        "aws_network_acl_rule",
        "aws_network_interface",
        "aws_network_interface_attachment",
        "aws_network_interface_permission",
        "aws_network_interface_sg_attachment",
        "aws_route",
        "aws_route53_vpc_association_authorization",
        "aws_route53_zone_association",
        "aws_route_table",
        "aws_route_table_association",
        "aws_security_group",
        "aws_security_group_rule",
        "aws_subnet",
        "aws_subnet_network_acl_association",
        "aws_vpc",
        "aws_vpc_dhcp_options",
        "aws_vpc_dhcp_options_association",
        "aws_vpc_ipv4_cidr_block_association",
        "aws_vpc_ipv6_cidr_block_association",
        "aws_vpc_security_group_egress_rule",
        "aws_vpc_security_group_ingress_rule",
        "aws_vpn_connection",
        "aws_vpn_connection_route",
        "aws_vpn_gateway",
        "aws_vpn_gateway_attachment",
        "aws_vpn_gateway_route_propagation",
        # AWS Cloud Control provider: exact EC2 types which do not have a
        # useful network-only family prefix below.
        "awscc_ec2_carrier_gateway",
        "awscc_ec2_customer_gateway",
        "awscc_ec2_dhcp_options",
        "awscc_ec2_egress_only_internet_gateway",
        "awscc_ec2_flow_log",
        "awscc_ec2_internet_gateway",
        "awscc_ec2_nat_gateway",
        "awscc_ec2_network_performance_metric_subscription",
        "awscc_ec2_prefix_list",
    }
)

NETWORK_RESOURCE_PREFIXES = (
    "aws_alb_",
    "aws_cloudwan_",
    "aws_dx_",
    "aws_ec2_client_vpn",
    "aws_ec2_instance_connect_endpoint",
    "aws_ec2_managed_prefix_list",
    "aws_ec2_transit_gateway",
    "aws_elb_",
    "aws_globalaccelerator_",
    "aws_lb_",
    "aws_networkfirewall_",
    "aws_network_interface_",
    "aws_networkmanager_",
    "aws_route53_resolver_",
    "aws_traffic_mirror_",
    "aws_verifiedaccess_",
    "aws_vpc_block_public_access",
    "aws_vpc_endpoint",
    "aws_vpc_ipam",
    "aws_vpc_peering_connection",
    "aws_vpc_security_group_vpc_association",
    # The AWS provider spells VPC Lattice as one word: vpclattice.
    "aws_vpclattice_",
    # AWS Cloud Control provider network-only services.
    "awscc_apigatewayv2_vpc_link",
    "awscc_directconnect_",
    "awscc_elasticloadbalancing_",
    "awscc_elasticloadbalancingv2_",
    "awscc_globalaccelerator_",
    "awscc_networkfirewall_",
    "awscc_networkmanager_",
    "awscc_route53resolver_",
    "awscc_vpclattice_",
    # Only network-specific AWS::EC2 families. Broad awscc_ec2_* matching
    # would incorrectly classify compute resources as shared-network state.
    "awscc_ec2_client_vpn_",
    "awscc_ec2_eip",
    "awscc_ec2_instance_connect_endpoint",
    "awscc_ec2_ipam",
    "awscc_ec2_local_gateway_route",
    "awscc_ec2_network_acl",
    "awscc_ec2_network_interface",
    "awscc_ec2_route",
    "awscc_ec2_security_group",
    "awscc_ec2_subnet",
    "awscc_ec2_traffic_mirror",
    "awscc_ec2_transit_gateway",
    "awscc_ec2_verified_access",
    "awscc_ec2_vpc",
    "awscc_ec2_vpn",
)

# These resources can materialize arbitrary infrastructure from a template or
# execute code during apply. Their contents cannot be proven network-safe by
# inspecting the outer plan, so application Terraform may not own them.
INDIRECT_PROVISIONING_RESOURCE_TYPES = frozenset(
    {
        "aws_cloudcontrolapi_resource",
        "aws_cloudformation_stack",
        "aws_cloudformation_stack_set",
        "aws_cloudformation_stack_set_instance",
        "aws_lambda_invocation",
        "aws_ram_principal_association",
        "aws_ram_resource_association",
        "aws_serverlessapplicationrepository_cloudformation_stack",
        "aws_servicecatalog_provisioned_product",
        "awscc_cloudformation_stack",
        "awscc_ram_resource_share",
        "awscc_servicecatalog_cloud_formation_provisioned_product",
    }
)

FORGET_ACTION = ("forget",)
APPROVED_MANAGED_RESOURCE_TYPES = frozenset(
    {
        "aws_apigatewayv2_api",
        "aws_apigatewayv2_api_mapping",
        "aws_apigatewayv2_authorizer",
        "aws_apigatewayv2_domain_name",
        "aws_apigatewayv2_integration",
        "aws_apigatewayv2_route",
        "aws_apigatewayv2_stage",
        "aws_cloudfront_response_headers_policy",
        "aws_cloudwatch_dashboard",
        "aws_cloudwatch_log_group",
        "aws_cloudwatch_log_metric_filter",
        "aws_cloudwatch_metric_alarm",
        "aws_db_proxy",
        "aws_db_proxy_default_target_group",
        "aws_db_proxy_target",
        "aws_iam_role",
        "aws_iam_role_policy",
        "aws_iam_role_policy_attachment",
        "aws_lambda_alias",
        "aws_lambda_function",
        "aws_lambda_layer_version",
        "aws_lambda_permission",
        "aws_lambda_provisioned_concurrency_config",
        "aws_s3_bucket",
        "aws_s3_bucket_cors_configuration",
        "aws_s3_bucket_lifecycle_configuration",
        "aws_s3_bucket_ownership_controls",
        "aws_s3_bucket_policy",
        "aws_s3_bucket_public_access_block",
        "aws_s3_bucket_server_side_encryption_configuration",
        "aws_s3_bucket_versioning",
        "aws_scheduler_schedule",
        "aws_scheduler_schedule_group",
        "aws_sns_topic",
        "aws_sns_topic_subscription",
        "aws_sqs_queue",
        "terraform_data",
    }
)
APPROVED_DATA_SOURCE_TYPES = frozenset(
    {
        "aws_api_gateway_domain_name",
        "aws_apigatewayv2_apis",
        "aws_ec2_transit_gateway_vpc_attachments",
        "aws_iam_policy_document",
        "aws_route",
        "aws_route_table",
        "aws_route_tables",
        "aws_s3_bucket",
        "aws_security_group",
        "aws_subnets",
        "aws_vpc",
    }
)
APPROVED_PROVIDER_NAMES = frozenset({"aws"})
APPROVED_PROVIDER_SOURCES = frozenset(
    {"hashicorp/aws", "registry.terraform.io/hashicorp/aws"}
)
# API Gateway imports are restricted elsewhere to the independently audited
# survivor. The proxy recovery imports are additionally bound here to the exact
# app-owned resource address and live identifier so another account resource
# cannot be adopted merely because it has the same Terraform type.
APPROVED_IMPORT_RESOURCE_TYPES = frozenset({"aws_apigatewayv2_api"})
APPROVED_IMPORT_IDENTITIES = frozenset(
    {
        (
            "aws_db_proxy",
            "module.proxy.aws_db_proxy.this",
            "uid-dev-portal-proxy",
        ),
        (
            "aws_db_proxy_default_target_group",
            "module.proxy.aws_db_proxy_default_target_group.this",
            "uid-dev-portal-proxy",
        ),
        (
            "aws_db_proxy_target",
            "module.proxy.aws_db_proxy_target.this",
            "uid-dev-portal-proxy/default/TRACKED_CLUSTER/uid-dev-postgresqlv2",
        ),
    }
)
DEFAULT_OWNERSHIP_MANIFEST = (
    Path(__file__).resolve().parents[1]
    / "state-owned-resources.json"
)
API_ENV_ROOTS = frozenset(
    (
        Path(__file__).resolve().parents[1]
        / "envs"
        / env
    ).resolve()
    for env in ("at", "dev", "prod")
)
DEV_ARCHIVE_COMPATIBILITY_FILE = (
    Path(__file__).resolve().parents[1]
    / "envs"
    / "dev"
    / "backend.tf"
).resolve()
_PORTAL_DOMAIN_LINE = re.compile(
    r"^\s*portal_domain_name\s*=.*$", re.MULTILINE
)
_PORTAL_DOMAIN_ASSIGNMENT = re.compile(
    r'^\s*portal_domain_name\s*=\s*"([^"\r\n]+)"\s*(?:#.*)?$',
    re.MULTILINE,
)
_PORTAL_DOMAIN_OWNERSHIP_LINE = re.compile(
    r"^\s*portal_domain_ownership\s*=.*$", re.MULTILINE
)
_PORTAL_DOMAIN_OWNERSHIP_ASSIGNMENT = re.compile(
    r'^\s*portal_domain_ownership\s*=\s*"(external|managed)"\s*(?:#.*)?$',
    re.MULTILINE,
)
_CERTIFICATE_ARN_LINE = re.compile(r"^\s*certificate_arn\s*=.*$", re.MULTILINE)
_CERTIFICATE_ARN_ASSIGNMENT = re.compile(
    r'^\s*certificate_arn\s*=\s*"([^"\r\n]+)"\s*(?:#.*)?$',
    re.MULTILINE,
)
_DNS_HOSTNAME = re.compile(
    r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?"
)
_BLOCK_HEADER = re.compile(
    r'(?m)^\s*(resource|data|module|provider|action|ephemeral)\s+"([^"\r\n]+)"'
    r'(?:\s+"([^"\r\n]+)")?\s*\{'
)
_TERRAFORM_HEADER = re.compile(r"(?m)^\s*terraform\s*\{")
_REQUIRED_PROVIDERS_HEADER = re.compile(r"(?m)^\s*required_providers\s*\{")
_PROVIDER_ENTRY = re.compile(r"(?m)^\s*([A-Za-z][A-Za-z0-9_-]*)\s*=\s*\{")
_PROVIDER_SOURCE = re.compile(r'\bsource\s*=\s*"([^"\r\n]+)"')
_PROVISIONER = re.compile(r'(?m)^\s*provisioner\s+"[^"\r\n]+"\s*\{')
_ACTION_TRIGGER = re.compile(r"(?m)^\s*action_trigger\s*\{")
_MODULE_SOURCE = re.compile(r'(?m)^\s*source\s*=\s*"([^"\r\n]+)"\s*$')
_HEREDOC_START = re.compile(r"<<-?\s*([A-Za-z_][A-Za-z0-9_]*)")


@dataclass(frozen=True)
class ProtectedTarget:
    resource_class: str
    identifiers: frozenset[str]
    resource_types: frozenset[str]
    resource_type_prefixes: tuple[str, ...]
    identity_attributes: frozenset[str]

    def matches_type(self, resource_type: str) -> bool:
        return resource_type in self.resource_types or resource_type.startswith(
            self.resource_type_prefixes
        )


@dataclass(frozen=True)
class OwnershipPolicy:
    resource_types: frozenset[str]
    resource_type_prefixes: tuple[str, ...]
    targets: tuple[ProtectedTarget, ...]

    def protects_type(self, resource_type: str) -> bool:
        return resource_type in self.resource_types or resource_type.startswith(
            self.resource_type_prefixes
        )


def _string_list(value: Any, field: str, *, allow_empty: bool = True) -> list[str]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise ValueError(f"ownership manifest {field} must be a list of strings")
    if not allow_empty and not value:
        raise ValueError(f"ownership manifest {field} must not be empty")
    if len(value) != len(set(value)):
        raise ValueError(f"ownership manifest {field} contains duplicates")
    return value


def load_ownership_policy(path: Path) -> OwnershipPolicy:
    """Load and fail closed on the versioned external-resource inventory."""

    with path.open(encoding="utf-8") as handle:
        document = json.load(handle)
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        raise ValueError("ownership manifest must be a schema_version 1 object")

    resource_types = _string_list(
        document.get("protected_resource_types"), "protected_resource_types"
    )
    prefixes = _string_list(
        document.get("protected_resource_prefixes"),
        "protected_resource_prefixes",
    )
    raw_targets = document.get("resources")
    if not isinstance(raw_targets, list) or not raw_targets:
        raise ValueError("ownership manifest resources must be a non-empty list")

    targets: list[ProtectedTarget] = []
    seen_classes: set[str] = set()
    for index, value in enumerate(raw_targets):
        if not isinstance(value, dict):
            raise ValueError(f"ownership manifest resources[{index}] must be an object")
        resource_class = value.get("class")
        if not isinstance(resource_class, str) or not resource_class:
            raise ValueError(f"ownership manifest resources[{index}].class is invalid")
        if resource_class in seen_classes:
            raise ValueError(f"ownership manifest repeats class {resource_class!r}")
        seen_classes.add(resource_class)

        identifiers = _string_list(
            value.get("identifiers"),
            f"resources[{index}].identifiers",
            allow_empty=False,
        )
        target_types = _string_list(
            value.get("resource_types", []),
            f"resources[{index}].resource_types",
        )
        target_prefixes = _string_list(
            value.get("resource_type_prefixes", []),
            f"resources[{index}].resource_type_prefixes",
        )
        if not target_types and not target_prefixes:
            raise ValueError(
                f"ownership manifest resources[{index}] has no Terraform type selector"
            )
        identity_attributes = _string_list(
            value.get("identity_attributes"),
            f"resources[{index}].identity_attributes",
            allow_empty=False,
        )
        targets.append(
            ProtectedTarget(
                resource_class=resource_class,
                identifiers=frozenset(identifiers),
                resource_types=frozenset(target_types),
                resource_type_prefixes=tuple(target_prefixes),
                identity_attributes=frozenset(identity_attributes),
            )
        )

    return OwnershipPolicy(
        resource_types=frozenset(resource_types),
        resource_type_prefixes=tuple(prefixes),
        targets=tuple(targets),
    )


def is_network_resource(resource_type: str) -> bool:
    """Return whether a Terraform resource type owns shared-network state."""

    return resource_type in NETWORK_RESOURCE_TYPES or resource_type.startswith(
        NETWORK_RESOURCE_PREFIXES
    )


def is_approved_managed_resource(resource_type: str) -> bool:
    return resource_type in APPROVED_MANAGED_RESOURCE_TYPES


def is_approved_data_source(data_type: str) -> bool:
    return data_type in APPROVED_DATA_SOURCE_TYPES


def is_forbidden_managed_resource(
    resource_type: str, policy: OwnershipPolicy | None = None
) -> bool:
    return (
        not is_approved_managed_resource(resource_type)
        or is_network_resource(resource_type)
        or resource_type in INDIRECT_PROVISIONING_RESOURCE_TYPES
        or (policy is not None and policy.protects_type(resource_type))
    )


def _leaf_strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from _leaf_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _leaf_strings(child)


def _contains_identifier(values: Iterable[str], identifiers: Iterable[str]) -> bool:
    """Match exact identifiers and provider composite IDs containing them."""

    return any(identifier in value for value in values for identifier in identifiers)


def _has_unknown_identity(value: Any, attributes: frozenset[str]) -> bool:
    """Return true when any declared identity field remains unknown after plan."""

    if isinstance(value, dict):
        for key, child in value.items():
            if key in attributes and _unknown_truthy(child):
                return True
            if _has_unknown_identity(child, attributes):
                return True
    elif isinstance(value, list):
        return any(_has_unknown_identity(child, attributes) for child in value)
    return False


def _unknown_truthy(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, dict):
        return any(_unknown_truthy(child) for child in value.values())
    if isinstance(value, list):
        return any(_unknown_truthy(child) for child in value)
    return False


def _planned_resources(module: Any) -> Iterator[dict[str, Any]]:
    if not isinstance(module, dict):
        return
    resources = module.get("resources", [])
    if isinstance(resources, list):
        for resource in resources:
            if isinstance(resource, dict):
                yield resource
    children = module.get("child_modules", [])
    if isinstance(children, list):
        for child in children:
            yield from _planned_resources(child)


def _configuration_resources(
    module: Any, module_address: str = ""
) -> Iterator[dict[str, Any]]:
    """Yield configuration resources with their complete module addresses."""

    if not isinstance(module, dict):
        return
    resources = module.get("resources", [])
    if isinstance(resources, list):
        for resource in resources:
            if isinstance(resource, dict):
                address = resource.get("address")
                if not isinstance(address, str):
                    yield resource
                    continue
                qualified = dict(resource)
                qualified["address"] = (
                    f"{module_address}.{address}" if module_address else address
                )
                yield qualified
    module_calls = module.get("module_calls", {})
    if isinstance(module_calls, dict):
        for name, call in module_calls.items():
            if isinstance(call, dict):
                child_address = (
                    f"{module_address}.module.{name}"
                    if module_address
                    else f"module.{name}"
                )
                yield from _configuration_resources(
                    call.get("module"), child_address
                )


def _references(value: Any) -> Iterator[str]:
    if isinstance(value, dict):
        references = value.get("references")
        if isinstance(references, list):
            for reference in references:
                if isinstance(reference, str):
                    yield reference
        for child in value.values():
            yield from _references(child)
    elif isinstance(value, list):
        for child in value:
            yield from _references(child)


def _address_matches_reference(address: str, reference: str) -> bool:
    # Configuration references are commonly module-relative and may omit an
    # instance key. Match only complete resource-address boundaries.
    candidate = reference.removesuffix(".id").removesuffix(".bucket")
    return (
        address == candidate
        or address.startswith(f"{candidate}[")
        or address.endswith(f".{candidate}")
        or f".{candidate}[" in address
    )


def _known_app_bucket_unknown_targets(plan: dict[str, Any]) -> frozenset[str]:
    """Find S3 configs whose unknown bucket comes from a known app bucket."""

    protected_names = set(_adopted_bucket_names(plan))
    all_buckets: set[str] = set()
    known_app_buckets: set[str] = set()
    for resource in plan.get("resource_changes", []):
        if not isinstance(resource, dict) or resource.get("type") != "aws_s3_bucket":
            continue
        address = resource.get("address")
        change = resource.get("change")
        if not isinstance(address, str) or not isinstance(change, dict):
            continue
        all_buckets.add(address)
        after = change.get("after")
        bucket = after.get("bucket") if isinstance(after, dict) else None
        if (
            isinstance(bucket, str)
            and bucket
            and bucket not in protected_names
            and change.get("importing") is None
        ):
            known_app_buckets.add(address)

    configuration = plan.get("configuration", {})
    root_module = (
        configuration.get("root_module", {})
        if isinstance(configuration, dict)
        else {}
    )
    safe_targets: set[str] = set()
    for resource in _configuration_resources(root_module):
        address = resource.get("address")
        expressions = resource.get("expressions")
        if not isinstance(address, str) or not isinstance(expressions, dict):
            continue
        bucket_expression = expressions.get("bucket")
        bucket_references = set(_references(bucket_expression))
        if not bucket_references:
            continue

        # `bucket = each.value.id` is safe only when the resource's for_each is
        # itself exclusively the known managed bucket collection. Any other
        # unmatched reference (data source, variable, local, module output, or
        # a mixed conditional) keeps the target identity unknown and blocked.
        direct_references = {
            reference
            for reference in bucket_references
            if not reference.startswith("each.")
        }
        provenance_references = direct_references
        if not direct_references:
            provenance_references = set(
                _references(resource.get("for_each_expression"))
            )
        exclusively_known = bool(provenance_references)
        for reference in provenance_references:
            matched = {
                bucket_address
                for bucket_address in all_buckets
                if _address_matches_reference(bucket_address, reference)
            }
            if not matched or not matched.issubset(known_app_buckets):
                exclusively_known = False
                break
        if exclusively_known:
            safe_targets.add(address)
    return frozenset(safe_targets)


def _configuration_address_matches(change_address: str, config_address: str) -> bool:
    return change_address == config_address or change_address.startswith(
        f"{config_address}["
    )


def _adopted_bucket_names(plan: dict[str, Any]) -> frozenset[str]:
    """Discover future adopted buckets from read-only data in this exact plan."""

    planned_values = plan.get("planned_values", {})
    root_module = (
        planned_values.get("root_module", {})
        if isinstance(planned_values, dict)
        else {}
    )
    names: set[str] = set()
    for resource in _planned_resources(root_module):
        if resource.get("mode") != "data" or resource.get("type") != "aws_s3_bucket":
            continue
        values = resource.get("values")
        if not isinstance(values, dict):
            continue
        for field in ("bucket", "id"):
            candidate = values.get(field)
            if isinstance(candidate, str) and candidate:
                names.add(candidate)
        arn = values.get("arn")
        if isinstance(arn, str) and arn.startswith("arn:aws:s3:::"):
            names.add(arn.removeprefix("arn:aws:s3:::"))
    return frozenset(names)


def _expected_gateway_contract(
    roots: Iterable[Path],
) -> tuple[str, str, str] | None:
    """Read the reviewed literal domain contract for API environment roots."""

    contracts: list[tuple[str, str, str]] = []
    for supplied_root in roots:
        root = supplied_root.resolve()
        if root not in API_ENV_ROOTS:
            continue
        tfvars = root / "terraform.tfvars"
        source = tfvars.read_text(encoding="utf-8")
        lines = _PORTAL_DOMAIN_LINE.findall(source)
        assignments = _PORTAL_DOMAIN_ASSIGNMENT.findall(source)
        if len(lines) != 1 or len(assignments) != 1:
            raise ValueError(
                f"{tfvars} must contain exactly one literal "
                'portal_domain_name = "..." assignment'
            )
        domain = assignments[0]
        if not _DNS_HOSTNAME.fullmatch(domain):
            raise ValueError(
                f"{tfvars} portal_domain_name is not one exact lower-case hostname"
            )
        ownership_lines = _PORTAL_DOMAIN_OWNERSHIP_LINE.findall(source)
        ownership_assignments = _PORTAL_DOMAIN_OWNERSHIP_ASSIGNMENT.findall(source)
        if len(ownership_lines) != 1 or len(ownership_assignments) != 1:
            raise ValueError(
                f"{tfvars} must contain exactly one literal "
                'portal_domain_ownership = "external|managed" assignment'
            )
        certificate_lines = _CERTIFICATE_ARN_LINE.findall(source)
        certificate_assignments = _CERTIFICATE_ARN_ASSIGNMENT.findall(source)
        if len(certificate_lines) != 1 or len(certificate_assignments) != 1:
            raise ValueError(
                f"{tfvars} must contain exactly one literal "
                'certificate_arn = "..." assignment'
            )
        contracts.append(
            (domain, ownership_assignments[0], certificate_assignments[0])
        )
    if len(set(contracts)) > 1:
        raise ValueError(
            "the supplied API environment roots disagree on the custom-domain contract"
        )
    return contracts[0] if contracts else None


def _deferred_external_domain_is_guarded(
    plan: dict[str, Any],
    resource: dict[str, Any],
    expected_domain: str,
    expected_certificate_arn: str,
) -> bool:
    """Recognize an apply-time read whose exact contract remains fail-closed."""

    address = resource.get("address")
    values = resource.get("values")
    if not isinstance(address, str) or not isinstance(values, dict):
        return False

    expected_values: dict[str, Any] = {
        "endpoint_configuration": [{"types": ["REGIONAL"]}],
        "security_policy": "TLS_1_2",
        "regional_certificate_arn": expected_certificate_arn,
    }
    changes = [
        change
        for change in plan.get("resource_changes", [])
        if isinstance(change, dict)
        and change.get("address") == address
        and change.get("mode") == "data"
        and change.get("type") == "aws_api_gateway_domain_name"
    ]
    if len(changes) != 1:
        return False
    change = changes[0].get("change")
    if not isinstance(change, dict) or change.get("actions") != ["read"]:
        return False
    after = change.get("after")
    after_unknown = change.get("after_unknown")
    if (
        not isinstance(after, dict)
        or after.get("domain_name") != expected_domain
        or not isinstance(after_unknown, dict)
    ):
        return False

    # Terraform may know part of a deferred data result. Every contract field
    # must either already equal the reviewed value or be explicitly marked
    # unknown in both the planned value and matching read change.
    for field, expected in expected_values.items():
        for known in (values, after):
            if field in known and known[field] != expected:
                return False
        if field not in values and not _unknown_truthy(after_unknown.get(field)):
            return False

    # A deferred lifecycle postcondition is represented as an unknown resource
    # check for this exact instance. Requiring it prevents an ordinary unguarded
    # data read from inheriting trust merely because provider values are unknown.
    return _external_domain_check_has_status(plan, address, "unknown")


def _external_domain_check_has_status(
    plan: dict[str, Any], address: str, status: str
) -> bool:
    """Require one exact external-domain lifecycle-check instance status."""

    checks = plan.get("checks", [])
    if not isinstance(checks, list):
        return False
    for check in checks:
        if not isinstance(check, dict) or check.get("status") != status:
            continue
        check_address = check.get("address")
        if (
            not isinstance(check_address, dict)
            or check_address.get("kind") != "resource"
            or check_address.get("mode") != "data"
        ):
            continue
        if check_address.get("type") != "aws_api_gateway_domain_name":
            continue
        instances = check.get("instances")
        if not isinstance(instances, list):
            continue
        if any(
            isinstance(instance, dict)
            and instance.get("status") == status
            and isinstance(instance.get("address"), dict)
            and instance["address"].get("to_display") == address
            for instance in instances
        ):
            return True
    return False


def _refreshed_external_domains_from_prior_state(
    plan: dict[str, Any],
) -> list[dict[str, Any]]:
    """Recover resolved plan-time reads omitted from ``planned_values``.

    Terraform records an unchanged data source read during planning in the
    refreshed ``prior_state`` but may omit it from ``planned_values``. Prior
    state alone is not proof that an instance is still active, so accept only
    the single currently configured block whose exact lifecycle check passed.
    """

    configuration = plan.get("configuration")
    configuration_root = (
        configuration.get("root_module")
        if isinstance(configuration, dict)
        else None
    )
    configured_domains = [
        resource
        for resource in _configuration_resources(configuration_root)
        if resource.get("mode") == "data"
        and resource.get("type") == "aws_api_gateway_domain_name"
        and isinstance(resource.get("address"), str)
    ]
    if len(configured_domains) != 1:
        return []
    configured_address = configured_domains[0]["address"]

    prior_state = plan.get("prior_state")
    prior_values = (
        prior_state.get("values") if isinstance(prior_state, dict) else None
    )
    prior_root = (
        prior_values.get("root_module")
        if isinstance(prior_values, dict)
        else None
    )
    domains: list[dict[str, Any]] = []
    for resource in _planned_resources(prior_root):
        address = resource.get("address")
        if (
            resource.get("mode") != "data"
            or resource.get("type") != "aws_api_gateway_domain_name"
            or not isinstance(address, str)
            or not _configuration_address_matches(address, configured_address)
            or not _external_domain_check_has_status(plan, address, "pass")
        ):
            continue
        domains.append(resource)
    return domains


def _gateway_plan_violations(
    plan: dict[str, Any],
    expected_domain: str | None,
    expected_ownership: str | None,
    expected_certificate_arn: str | None,
) -> list[str]:
    """Bind the saved API plan to one reviewed domain, mapping and stage."""

    if expected_domain is None:
        return []
    planned_values = plan.get("planned_values")
    root_module = (
        planned_values.get("root_module")
        if isinstance(planned_values, dict)
        else None
    )
    resources = list(_planned_resources(root_module))
    managed_resources = [
        resource
        for resource in resources
        if resource.get("mode", "managed") == "managed"
    ]
    data_resources = [
        resource for resource in resources if resource.get("mode") == "data"
    ]
    violations: list[str] = []

    by_type: dict[str, list[dict[str, Any]]] = {}
    for resource in managed_resources:
        resource_type = resource.get("type")
        if isinstance(resource_type, str):
            by_type.setdefault(resource_type, []).append(resource)

    for resource_type in ("aws_apigatewayv2_api_mapping", "aws_apigatewayv2_stage"):
        count = len(by_type.get(resource_type, []))
        if count != 1:
            violations.append(
                f"plan:{resource_type}\t{count} instances\texpected_exactly_1"
            )

    managed_domains = by_type.get("aws_apigatewayv2_domain_name", [])
    external_domains = [
        resource
        for resource in data_resources
        if resource.get("type") == "aws_api_gateway_domain_name"
    ]
    if not external_domains:
        external_domains = _refreshed_external_domains_from_prior_state(plan)
    expected_managed_count = 1 if expected_ownership == "managed" else 0
    expected_external_count = 1 if expected_ownership == "external" else 0
    if len(managed_domains) != expected_managed_count:
        violations.append(
            "plan:aws_apigatewayv2_domain_name\t"
            f"{len(managed_domains)} instances\texpected_exactly_{expected_managed_count}"
        )
    if len(external_domains) != expected_external_count:
        violations.append(
            "plan:data.aws_api_gateway_domain_name\t"
            f"{len(external_domains)} instances\texpected_exactly_{expected_external_count}"
        )

    if len(managed_domains) == 1:
        values = managed_domains[0].get("values")
        actual = values.get("domain_name") if isinstance(values, dict) else None
        if actual != expected_domain:
            violations.append(
                "plan:aws_apigatewayv2_domain_name\t"
                f"{actual!r}\texpected_{expected_domain!r}"
            )

    if len(external_domains) == 1:
        values = external_domains[0].get("values")
        actual = values.get("domain_name") if isinstance(values, dict) else None
        endpoint_configuration = (
            values.get("endpoint_configuration") if isinstance(values, dict) else None
        )
        endpoint = (
            endpoint_configuration[0]
            if isinstance(endpoint_configuration, list)
            and len(endpoint_configuration) == 1
            else None
        )
        if actual != expected_domain:
            violations.append(
                "plan:data.aws_api_gateway_domain_name\t"
                f"{actual!r}\texpected_{expected_domain!r}"
            )
        known_contract_is_valid = (
            isinstance(endpoint, dict)
            and endpoint.get("types") == ["REGIONAL"]
            and isinstance(values, dict)
            and values.get("security_policy") == "TLS_1_2"
            and values.get("regional_certificate_arn")
            == expected_certificate_arn
        )
        deferred_contract_is_guarded = (
            expected_certificate_arn is not None
            and _deferred_external_domain_is_guarded(
                plan,
                external_domains[0],
                expected_domain,
                expected_certificate_arn,
            )
        )
        if not known_contract_is_valid and not deferred_contract_is_guarded:
            violations.append(
                "plan:data.aws_api_gateway_domain_name\tinvalid\t"
                "expected_reviewed_REGIONAL_TLS_1_2_certificate"
            )

    mappings = by_type.get("aws_apigatewayv2_api_mapping", [])
    if len(mappings) == 1:
        values = mappings[0].get("values")
        if not isinstance(values, dict) or values.get("api_mapping_key") not in (
            None,
            "",
        ):
            violations.append(
                "plan:aws_apigatewayv2_api_mapping\tnon_root\t"
                "expected_root_mapping"
            )
        elif values.get("domain_name") != expected_domain:
            violations.append(
                "plan:aws_apigatewayv2_api_mapping\twrong_or_unknown_domain\t"
                f"expected_{expected_domain!r}"
            )

    stages = by_type.get("aws_apigatewayv2_stage", [])
    if len(stages) == 1:
        values = stages[0].get("values")
        if (
            not isinstance(values, dict)
            or values.get("name") != "$default"
            or values.get("auto_deploy") is not True
        ):
            violations.append(
                "plan:aws_apigatewayv2_stage\tinvalid\t"
                "expected_auto_deployed_$default"
            )
    return violations


def _protected_target_classes(
    address: str,
    resource_type: str,
    change: dict[str, Any],
    policy: OwnershipPolicy,
    adopted_buckets: frozenset[str],
    known_app_bucket_unknown_targets: frozenset[str],
) -> list[str]:
    values = set(
        _leaf_strings(
            {
                "before": change.get("before"),
                "after": change.get("after"),
                "importing": change.get("importing"),
            }
        )
    )
    after_unknown = change.get("after_unknown")
    known_app_bucket_reference = any(
        _configuration_address_matches(address, config_address)
        for config_address in known_app_bucket_unknown_targets
    )
    classes: list[str] = []
    for target in policy.targets:
        if not target.matches_type(resource_type):
            continue
        if _contains_identifier(values, target.identifiers):
            classes.append(target.resource_class)
        elif _has_unknown_identity(
            after_unknown, target.identity_attributes
        ) and not (
            known_app_bucket_reference
            and resource_type.startswith("aws_s3_")
            and "bucket" in target.identity_attributes
        ):
            classes.append(f"{target.resource_class}:unknown_identity")
    if resource_type.startswith("aws_s3_") and _contains_identifier(
        values, adopted_buckets
    ):
        classes.append("adopted_s3_bucket_from_plan")
    elif (
        resource_type.startswith("aws_s3_")
        and not known_app_bucket_reference
        and _has_unknown_identity(
            after_unknown, frozenset({"bucket"})
        )
    ):
        classes.append("adopted_s3_bucket_from_plan:unknown_identity")
    return sorted(set(classes))


def plan_violations(
    plan: dict[str, Any],
    policy: OwnershipPolicy | None = None,
    *,
    expected_gateway_domain: str | None = None,
    expected_gateway_domain_ownership: str | None = None,
    expected_gateway_certificate_arn: str | None = None,
) -> list[str]:
    """Find forbidden State-owned resource ownership in Terraform plan JSON."""

    policy = policy or load_ownership_policy(DEFAULT_OWNERSHIP_MANIFEST)

    changes = plan.get("resource_changes")
    if not isinstance(changes, list):
        raise ValueError("Terraform plan JSON has no resource_changes list")
    adopted_buckets = _adopted_bucket_names(plan)
    known_app_bucket_unknown_targets = _known_app_bucket_unknown_targets(plan)

    violations: list[str] = []
    violations.extend(
        _gateway_plan_violations(
            plan,
            expected_gateway_domain,
            expected_gateway_domain_ownership,
            expected_gateway_certificate_arn,
        )
    )
    for field, expected in (("complete", True), ("errored", False)):
        if plan.get(field) is not expected:
            violations.append(
                f"plan:metadata\t{field}\t{plan.get(field)!r}\texpected_{expected!r}"
            )
    applyable = plan.get("applyable")
    if not isinstance(applyable, bool):
        violations.append(
            f"plan:metadata\tapplyable\t{applyable!r}\texpected_boolean"
        )
    for field in (
        "action_invocations",
        "deferred_action_invocations",
        "deferred_changes",
    ):
        value = plan.get(field, [])
        if not isinstance(value, list):
            raise ValueError(f"Terraform plan {field} must be a list when present")
        if value:
            violations.append(f"plan:{field}\tnonempty\tforbidden")
    api_instances = [
        resource
        for resource in changes
        if isinstance(resource, dict)
        and resource.get("mode", "managed") == "managed"
        and resource.get("type") == "aws_apigatewayv2_api"
    ]
    if len(api_instances) > 1:
        violations.append(
            f"plan:aws_apigatewayv2_api\t{len(api_instances)} instances\tmaximum_1"
        )
    if applyable is False:
        for resource in changes:
            if not isinstance(resource, dict):
                continue
            change = resource.get("change")
            actions = change.get("actions") if isinstance(change, dict) else None
            if actions not in (["no-op"], ["read"]):
                violations.append(
                    "plan:metadata\tapplyable\tfalse_with_mutating_or_invalid_actions"
                )
                break
    for resource in changes:
        if not isinstance(resource, dict):
            raise ValueError("Terraform resource_changes entries must be objects")

        mode = resource.get("mode", "managed")
        if mode == "data":
            data_type = resource.get("type")
            address = resource.get("address", data_type)
            if not isinstance(data_type, str):
                raise ValueError("Terraform data resource change has no string type")
            if not is_approved_data_source(data_type):
                violations.append(
                    f"plan:{address}\t{data_type}\tdata\tunapproved_data_source"
                )
            continue
        if mode != "managed":
            raise ValueError(f"unsupported Terraform resource mode: {mode!r}")

        resource_type = resource.get("type")
        if not isinstance(resource_type, str):
            raise ValueError("Terraform managed resource change has no string type")
        change = resource.get("change")
        address = resource.get("address", resource_type)
        if not isinstance(change, dict):
            raise ValueError(f"{address} has no change object")
        raw_actions = change.get("actions")
        if not isinstance(raw_actions, list) or not raw_actions or not all(
            isinstance(action, str) for action in raw_actions
        ):
            raise ValueError(f"{address} has invalid change actions")
        actions = tuple(raw_actions)
        importing_value = change.get("importing")
        importing = importing_value is not None

        protected_classes = _protected_target_classes(
            address,
            resource_type,
            change,
            policy,
            adopted_buckets,
            known_app_bucket_unknown_targets,
        )
        import_id = (
            importing_value.get("id")
            if isinstance(importing_value, dict)
            else None
        )
        approved_import = resource_type in APPROVED_IMPORT_RESOURCE_TYPES or (
            isinstance(import_id, str)
            and (resource_type, address, import_id) in APPROVED_IMPORT_IDENTITIES
        )
        if importing and not approved_import:
            detail = ",".join(actions)
            violations.append(
                f"plan:{address}\t{resource_type}\t{detail}+import\tunapproved_import"
            )
            continue
        if (
            not is_forbidden_managed_resource(resource_type, policy)
            and not protected_classes
        ):
            continue

        # `forget` is emitted by a `removed` block with destroy=false. It is
        # the sole managed transition which relinquishes ownership without an
        # API mutation. Even a no-op declaration continues forbidden ownership.
        if actions != FORGET_ACTION or importing:
            detail = ",".join(actions)
            if importing:
                detail = f"{detail}+import"
            classification = (
                ",".join(protected_classes)
                if protected_classes
                else "protected_resource_family"
            )
            violations.append(
                f"plan:{address}\t{resource_type}\t{detail}\t{classification}"
            )
    return violations


# Backwards-compatible name for callers which imported the first implementation.
network_mutations = plan_violations


def _mask_hcl_comments(text: str) -> str:
    """Replace HCL comments with spaces while retaining offsets/newlines."""

    chars = list(text)
    index = 0
    state = "normal"
    while index < len(chars):
        char = chars[index]
        following = chars[index + 1] if index + 1 < len(chars) else ""
        if state == "string":
            if char == "\\":
                index += 2
                continue
            if char == '"':
                state = "normal"
            index += 1
            continue
        if state == "line-comment":
            if char in "\r\n":
                state = "normal"
            else:
                chars[index] = " "
            index += 1
            continue
        if state == "block-comment":
            if char == "*" and following == "/":
                chars[index] = chars[index + 1] = " "
                index += 2
                state = "normal"
            else:
                if char not in "\r\n":
                    chars[index] = " "
                index += 1
            continue

        if char == '"':
            state = "string"
            index += 1
        elif char == "#":
            chars[index] = " "
            state = "line-comment"
            index += 1
        elif char == "/" and following == "/":
            chars[index] = chars[index + 1] = " "
            state = "line-comment"
            index += 2
        elif char == "/" and following == "*":
            chars[index] = chars[index + 1] = " "
            state = "block-comment"
            index += 2
        else:
            index += 1
    return "".join(chars)


def _mask_hcl_heredocs(text: str) -> str:
    """Mask heredoc bodies so embedded scripts cannot look like HCL blocks."""

    lines = text.splitlines(keepends=True)
    active_label: str | None = None
    for index, line in enumerate(lines):
        if active_label is not None:
            if line.strip() == active_label:
                active_label = None
            else:
                lines[index] = "".join(
                    char if char in "\r\n" else " " for char in line
                )
            continue

        match = _HEREDOC_START.search(line)
        if match is not None:
            # HCL heredoc markers occur outside quoted strings. Avoid treating
            # a literal marker in a normal quoted value as a heredoc.
            prefix = line[: match.start()]
            if prefix.count('"') % 2 == 0:
                active_label = match.group(1)
    return "".join(lines)


def _masked_hcl(text: str) -> str:
    return _mask_hcl_heredocs(_mask_hcl_comments(text))


def _matching_brace(text: str, opening: int) -> int:
    depth = 0
    in_string = False
    index = opening
    while index < len(text):
        char = text[index]
        if in_string:
            if char == "\\":
                index += 2
                continue
            if char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    raise ValueError("unterminated HCL block")


def _brace_depth_before(text: str, stop: int) -> int:
    depth = 0
    in_string = False
    index = 0
    while index < stop:
        char = text[index]
        if in_string:
            if char == "\\":
                index += 2
                continue
            if char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        index += 1
    return depth


def _hcl_required_providers(text: str) -> Iterator[tuple[str, str | None]]:
    """Yield literal local/provider-source pairs from required_providers."""

    masked = _masked_hcl(text)
    for terraform_match in _TERRAFORM_HEADER.finditer(masked):
        terraform_open = terraform_match.end() - 1
        terraform_close = _matching_brace(masked, terraform_open)
        terraform_body = masked[terraform_open + 1 : terraform_close]
        for required_match in _REQUIRED_PROVIDERS_HEADER.finditer(terraform_body):
            required_open = required_match.end() - 1
            required_close = _matching_brace(terraform_body, required_open)
            required_body = terraform_body[required_open + 1 : required_close]
            for entry in _PROVIDER_ENTRY.finditer(required_body):
                if _brace_depth_before(required_body, entry.start()) != 0:
                    continue
                entry_open = entry.end() - 1
                entry_close = _matching_brace(required_body, entry_open)
                entry_body = required_body[entry_open + 1 : entry_close]
                sources = _PROVIDER_SOURCE.findall(entry_body)
                yield entry.group(1), sources[0] if len(sources) == 1 else None


def _is_approved_required_provider(
    path: Path, provider_name: str, source: str | None
) -> bool:
    if (
        provider_name in APPROVED_PROVIDER_NAMES
        and source in APPROVED_PROVIDER_SOURCES
    ):
        return True
    return (
        path.resolve() == DEV_ARCHIVE_COMPATIBILITY_FILE
        and provider_name == "archive"
        and source == "hashicorp/archive"
    )


def _hcl_blocks(text: str) -> Iterator[tuple[str, str, str | None, str]]:
    """Yield (kind, first label, second label, body) for top-level blocks."""

    masked = _masked_hcl(text)
    for match in _BLOCK_HEADER.finditer(masked):
        opening = match.end() - 1
        closing = _matching_brace(masked, opening)
        yield match.group(1), match.group(2), match.group(3), masked[opening + 1 : closing]


def _is_local_module_source(source: str) -> bool:
    return source.startswith("./") or source.startswith("../")


def _nested_key(value: Any, key: str) -> bool:
    if isinstance(value, dict):
        return key in value or any(_nested_key(child, key) for child in value.values())
    if isinstance(value, list):
        return any(_nested_key(child, key) for child in value)
    return False


def _json_named_blocks(value: Any, block_kind: str, path: Path) -> Iterator[tuple[str, Any]]:
    if value is None:
        return
    if not isinstance(value, dict):
        raise ValueError(f"{path}: {block_kind} must be a JSON object")
    for name, body in value.items():
        if not isinstance(name, str) or not isinstance(body, (dict, list)):
            raise ValueError(f"{path}: malformed {block_kind} block {name!r}")
        yield name, body


def _json_resource_blocks(value: Any, path: Path) -> Iterator[tuple[str, str, Any]]:
    if value is None:
        return
    if not isinstance(value, dict):
        raise ValueError(f"{path}: resource must be a JSON object")
    for resource_type, named in value.items():
        if not isinstance(resource_type, str) or not isinstance(named, dict):
            raise ValueError(f"{path}: malformed resource family {resource_type!r}")
        for name, body in named.items():
            if not isinstance(name, str) or not isinstance(body, (dict, list)):
                raise ValueError(f"{path}: malformed resource {resource_type}.{name}")
            yield resource_type, name, body


def _source_file_violations(
    path: Path, policy: OwnershipPolicy
) -> tuple[list[str], list[str]]:
    """Return violations and literal local module sources in one source file."""

    violations: list[str] = []
    local_sources: list[str] = []
    location = str(path)

    if path.name.endswith(".tf.json"):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}: invalid Terraform JSON: {exc}") from exc
        if not isinstance(document, dict):
            raise ValueError(f"{path}: Terraform JSON must be an object")
        if document.get("check") not in (None, {}):
            violations.append(
                f"{location}: JSON check blocks are forbidden because scoped "
                "data-source provider safety cannot be proven"
            )

        terraform = document.get("terraform", {})
        if not isinstance(terraform, dict):
            raise ValueError(f"{path}: terraform must be a JSON object")
        required = terraform.get("required_providers", {})
        if not isinstance(required, dict):
            raise ValueError(f"{path}: required_providers must be a JSON object")
        for provider_name, requirement in required.items():
            source = requirement.get("source") if isinstance(requirement, dict) else None
            if not _is_approved_required_provider(path, provider_name, source):
                violations.append(
                    f"{location}: required provider {provider_name!r} has "
                    f"unapproved source {source!r}"
                )

        providers = document.get("provider", {})
        if not isinstance(providers, dict):
            raise ValueError(f"{path}: provider must be a JSON object")
        for provider_name in providers:
            if provider_name not in APPROVED_PROVIDER_NAMES:
                violations.append(
                    f"{location}: provider.{provider_name} is not locally approved"
                )

        for resource_type, name, body in _json_resource_blocks(
            document.get("resource"), path
        ):
            if is_forbidden_managed_resource(resource_type, policy):
                violations.append(
                    f"{location}: resource.{resource_type}.{name} declares forbidden ownership"
                )
            if _nested_key(body, "provisioner"):
                violations.append(
                    f"{location}: resource.{resource_type}.{name} uses a provisioner"
                )
            if _nested_key(body, "action_trigger"):
                violations.append(
                    f"{location}: resource.{resource_type}.{name} uses action_trigger"
                )

        for action_type, name, _body in _json_resource_blocks(
            document.get("action"), path
        ):
            violations.append(
                f"{location}: action.{action_type}.{name} can execute during apply"
            )
        for ephemeral_type, name, _body in _json_resource_blocks(
            document.get("ephemeral"), path
        ):
            violations.append(
                f"{location}: ephemeral.{ephemeral_type}.{name} can execute during plan"
            )

        for data_type, name, _body in _json_resource_blocks(document.get("data"), path):
            if not is_approved_data_source(data_type):
                violations.append(
                    f"{location}: data.{data_type}.{name} uses an unapproved provider"
                )

        for name, body in _json_named_blocks(document.get("module"), "module", path):
            bodies = body if isinstance(body, list) else [body]
            for instance in bodies:
                if not isinstance(instance, dict) or not isinstance(
                    instance.get("source"), str
                ):
                    violations.append(
                        f"{location}: module.{name} must use one literal local source"
                    )
                    continue
                source = instance["source"]
                if _is_local_module_source(source):
                    local_sources.append(source)
                else:
                    violations.append(
                        f"{location}: module.{name} uses forbidden non-local source {source!r}"
                    )
        return violations, local_sources

    try:
        text = path.read_text(encoding="utf-8")
        blocks = list(_hcl_blocks(text))
        required_providers = list(_hcl_required_providers(text))
    except ValueError as exc:
        raise ValueError(f"{path}: {exc}") from exc
    for provider_name, source in required_providers:
        if not _is_approved_required_provider(path, provider_name, source):
            violations.append(
                f"{location}: required provider {provider_name!r} has "
                f"unapproved source {source!r}"
            )
    for kind, first, second, body in blocks:
        if kind == "resource":
            if second is None:
                raise ValueError(f"{path}: malformed resource block")
            if is_forbidden_managed_resource(first, policy):
                violations.append(
                    f"{location}: resource.{first}.{second} declares forbidden ownership"
                )
            if _PROVISIONER.search(body):
                violations.append(
                    f"{location}: resource.{first}.{second} uses a provisioner"
                )
            if _ACTION_TRIGGER.search(body):
                violations.append(
                    f"{location}: resource.{first}.{second} uses action_trigger"
                )
        elif kind == "data" and not is_approved_data_source(first):
            violations.append(
                f"{location}: data.{first}.{second} uses an unapproved provider"
            )
        elif kind == "provider" and first not in APPROVED_PROVIDER_NAMES:
            violations.append(f"{location}: provider.{first} is not locally approved")
        elif kind == "action":
            violations.append(
                f"{location}: action.{first}.{second} can execute during apply"
            )
        elif kind == "ephemeral":
            violations.append(
                f"{location}: ephemeral.{first}.{second} can execute during plan"
            )
        elif kind == "module":
            source_matches = _MODULE_SOURCE.findall(body)
            if len(source_matches) != 1:
                violations.append(
                    f"{location}: module.{first} must use one literal local source"
                )
            elif _is_local_module_source(source_matches[0]):
                local_sources.append(source_matches[0])
            else:
                violations.append(
                    f"{location}: module.{first} uses forbidden non-local source "
                    f"{source_matches[0]!r}"
                )
    return violations, local_sources


def source_violations(
    roots: Iterable[Path], policy: OwnershipPolicy | None = None
) -> list[str]:
    """Audit roots and their transitively referenced local modules."""

    policy = policy or load_ownership_policy(DEFAULT_OWNERSHIP_MANIFEST)
    pending = [root.resolve() for root in roots]
    visited: set[Path] = set()
    violations: list[str] = []
    while pending:
        root = pending.pop()
        if root in visited:
            continue
        visited.add(root)
        if not root.is_dir():
            raise ValueError(f"Terraform root/module is not a directory: {root}")
        if ".terraform" in root.parts:
            raise ValueError(f"refusing to audit generated .terraform content: {root}")

        files = sorted(root.glob("*.tf")) + sorted(root.glob("*.tf.json"))
        for path in files:
            file_violations, local_sources = _source_file_violations(path, policy)
            violations.extend(file_violations)
            for source in local_sources:
                child = (root / source).resolve()
                if ".terraform" in child.parts:
                    violations.append(
                        f"{path}: local module source {source!r} enters .terraform"
                    )
                else:
                    pending.append(child)
    return sorted(set(violations))


def _load_plan(path: str) -> dict[str, Any]:
    if path == "-":
        value = json.load(sys.stdin)
    else:
        with Path(path).open(encoding="utf-8") as handle:
            value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError("Terraform plan JSON must be an object")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Fail if application Terraform owns or can mutate "
            "State of Utah-owned resources."
        )
    )
    parser.add_argument(
        "--plan-json",
        metavar="PATH|-",
        help="terraform show -json output, or - to read it from stdin",
    )
    parser.add_argument(
        "--terraform-root",
        action="append",
        default=[],
        metavar="PATH",
        help=(
            "Terraform root to source-audit; may be repeated and follows local modules"
        ),
    )
    parser.add_argument(
        "--ownership-manifest",
        type=Path,
        default=DEFAULT_OWNERSHIP_MANIFEST,
        metavar="PATH",
        help=(
            "versioned State-owned resource inventory "
            f"(default: {DEFAULT_OWNERSHIP_MANIFEST})"
        ),
    )
    args = parser.parse_args()
    if args.plan_json is None and not args.terraform_root:
        parser.error("at least one --plan-json or --terraform-root is required")

    try:
        policy = load_ownership_policy(args.ownership_manifest)
        terraform_roots = [Path(root) for root in args.terraform_root]
        violations = source_violations(terraform_roots, policy)
        if args.plan_json is not None:
            gateway_contract = _expected_gateway_contract(terraform_roots)
            violations.extend(
                plan_violations(
                    _load_plan(args.plan_json),
                    policy,
                    expected_gateway_domain=(
                        gateway_contract[0] if gateway_contract is not None else None
                    ),
                    expected_gateway_domain_ownership=(
                        gateway_contract[1] if gateway_contract is not None else None
                    ),
                    expected_gateway_certificate_arn=(
                        gateway_contract[2] if gateway_contract is not None else None
                    ),
                )
            )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(
            f"ERROR: cannot validate Terraform State-owned resource boundary: {exc}",
            file=sys.stderr,
        )
        return 2

    if violations:
        print(
            "ERROR: application Terraform owns or can mutate State of Utah-owned "
            "infrastructure or data:",
            file=sys.stderr,
        )
        for violation in sorted(set(violations)):
            print(f"  {violation}", file=sys.stderr)
        print(
            "Use data sources/IDs for reads. Relinquish historical state with a "
            "reviewed removed block (destroy=false), and send required changes to "
            "the State resource owner.",
            file=sys.stderr,
        )
        return 1

    print(
        "PASS: Terraform sources and plan do not own or mutate "
        "State of Utah-owned resources"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
