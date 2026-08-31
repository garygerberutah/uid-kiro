#!/usr/bin/env python3
"""Audit every UID Portal Lambda ingress path without changing AWS.

The deploy creates one function per HTTP route, one Ping authorizer, two
Lambda-to-Lambda workers, and the scheduled jobs declared in routes.yaml.  A
request function is intentionally invokable by API Gateway only through its
``live`` alias and only from the one supplied HTTP API.  Workers and schedules
use exact same-account IAM identity grants and therefore need no Lambda
resource-policy statement.

This script reads the live account with the AWS CLI and fails on:

* more than one tagged/historically named UID Portal HTTP API in the target
  account and Region,
  or a survivor whose id/name differs from the reviewed Terraform outputs;
* default-endpoint, stage, custom-domain, route, authorizer, or integration drift;
* Lambda runtime, execution-role, handler, VPC, or selected environment drift;
* a missing, unexpected, unqualified, or otherwise extra Lambda permission;
* a permission whose principal, action, resource, SourceArn, or SourceAccount
  is too broad;
* any function URL or event-source mapping on a UID Portal function; or
* any Lambda target group that names a UID Portal function.

It is deliberately read-only.  The AWS CLI is used instead of adding boto3 as
a repository dependency.

Important limitation: a same-account IAM principal can invoke Lambda using an
identity policy even when the function has no resource policy.  This audit
cannot enumerate every IAM identity policy, permission boundary, SCP, or
session policy in the account.  It proves the absence of alternate
service/resource-based ingress found through the checked Lambda, API Gateway,
event-source, function-URL, and ALB control planes; CloudTrail/IAM Access
Analyzer remains necessary for account-wide identity-policy assurance.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

APP_ROOT = Path(__file__).resolve().parents[6]
DEFAULT_MANIFEST = APP_ROOT / "services" / "api" / "routes" / "routes.yaml"
API_GATEWAY_PRINCIPAL = {"Service": "apigateway.amazonaws.com"}
UID_PORTAL_FUNCTION_PREFIX = "uid-portal-"
EXPECTED_FUNCTION_COUNT = 49
EXPECTED_ROUTE_COUNT = 42
EXPECTED_PROTECTED_ROUTE_COUNT = 38
PING_ISSUER = "https://sso.mylogin.utah.gov:443/am/oauth2"
PING_JWKS_URL = f"{PING_ISSUER}/connect/jwk_uri"
PING_AUDIENCE = "7ZokREaGUFCgJprj3JX48Aa2tsrbsRbFwgeE"
PING_SCOPE_CLAIM = "scope"
PING_REQUIRED_SCOPES = frozenset(("openid", "profile", "email", "directory"))
PING_AUTHORIZED_PARTY_CLAIM = "azp"
PING_AUTHORIZED_PARTY_VALUE = PING_AUDIENCE
PING_TOKEN_TYPE_SOURCE = "header"
PING_TOKEN_TYPE_NAME = "typ"
PING_TOKEN_TYPE_VALUE = "at+jwt"
IDENTITY_POLICY_LIMITATION = (
    "Same-account IAM identity policies can invoke Lambda without a Lambda "
    "resource policy; this audit cannot enumerate every identity policy, "
    "permission boundary, SCP, or session policy. Review IAM Access Analyzer "
    "and CloudTrail for account-wide identity-policy assurance."
)
_API_ID = re.compile(r"^[a-z0-9]{10}$")
_ENV_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$")
_REGION = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-\d$")
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
_VPC_ID = re.compile(r"^vpc-[0-9a-f]{8,17}$")
_SUBNET_ID = re.compile(r"^subnet-[0-9a-f]{8,17}$")
_SECURITY_GROUP_ID = re.compile(r"^sg-[0-9a-f]{8,17}$")
_SELECTED_ENVIRONMENT_QUERY = (
    "{Runtime:Runtime,Role:Role,Handler:Handler,"
    "VpcConfig:{VpcId:VpcConfig.VpcId,SubnetIds:VpcConfig.SubnetIds,"
    "SecurityGroupIds:VpcConfig.SecurityGroupIds,"
    "Ipv6AllowedForDualStack:VpcConfig.Ipv6AllowedForDualStack},"
    "UID_RUNTIME:Environment.Variables.UID_RUNTIME,"
    "DEV_AUTH_BYPASS:Environment.Variables.DEV_AUTH_BYPASS,"
    "REQUIRE_AUTHENTICATION:Environment.Variables.REQUIRE_AUTHENTICATION,"
    "REQUIRED_ROLES:Environment.Variables.REQUIRED_ROLES,"
    "API_ROUTE_ROLES:Environment.Variables.API_ROUTE_ROLES,"
    "API_ALLOWED_HOSTS:Environment.Variables.API_ALLOWED_HOSTS,"
    "OIDC_ISSUER:Environment.Variables.OIDC_ISSUER,"
    "OIDC_JWKS_URL:Environment.Variables.OIDC_JWKS_URL,"
    "OIDC_AUDIENCE:Environment.Variables.OIDC_AUDIENCE,"
    "OIDC_UTAH_ID_CLAIM:Environment.Variables.OIDC_UTAH_ID_CLAIM,"
    "OIDC_SCOPE_CLAIM:Environment.Variables.OIDC_SCOPE_CLAIM,"
    "OIDC_REQUIRED_SCOPES:Environment.Variables.OIDC_REQUIRED_SCOPES,"
    "OIDC_AUTHORIZED_PARTY_CLAIM:Environment.Variables.OIDC_AUTHORIZED_PARTY_CLAIM,"
    "OIDC_AUTHORIZED_PARTY_VALUE:Environment.Variables.OIDC_AUTHORIZED_PARTY_VALUE,"
    "OIDC_TOKEN_TYPE_SOURCE:Environment.Variables.OIDC_TOKEN_TYPE_SOURCE,"
    "OIDC_TOKEN_TYPE_NAME:Environment.Variables.OIDC_TOKEN_TYPE_NAME,"
    "OIDC_TOKEN_TYPE_VALUE:Environment.Variables.OIDC_TOKEN_TYPE_VALUE}"
)


@dataclass(frozen=True)
class ExpectedFunction:
    function_id: str
    name: str
    kind: str
    alias_arn: str
    source_arn: str | None = None
    source_account: str | None = None
    integration_uri: str | None = None
    route_key: str | None = None
    authentication_required: bool | None = None
    roles: tuple[str, ...] = ()
    identity_sources: tuple[str, ...] = ()
    authorizer_ttl: int | None = None
    runtime: str = "python3.13"
    role_arn: str | None = None
    handler: str | None = None


@dataclass(frozen=True)
class Finding:
    code: str
    subject: str
    detail: str


@dataclass(frozen=True)
class ExpectedVpcConfig:
    vpc_id: str
    vpc_ipv4_cidr: str
    subnet_ids: frozenset[str]
    security_group_ids: frozenset[str]


class AwsCliError(RuntimeError):
    """A read failed, so a clean account cannot be asserted."""


class AwsCli:
    def __init__(self, *, region: str, profile: str | None = None):
        self.region = region
        self.base = ["aws", "--region", region, "--output", "json"]
        if profile:
            self.base[1:1] = ["--profile", profile]
        self.env = {**os.environ, "AWS_PAGER": ""}

    def json(self, *args: str, missing_ok: bool = False) -> dict[str, Any] | None:
        command = [*self.base, *args]
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                env=self.env,
            )
        except FileNotFoundError as exc:
            raise AwsCliError("AWS CLI was not found on PATH") from exc
        if completed.returncode != 0:
            error = completed.stderr.strip() or completed.stdout.strip()
            if missing_ok and (
                "ResourceNotFoundException" in error
                or "ResourceNotFound" in error
                or "not found" in error.lower()
            ):
                return None
            rendered = " ".join(command)
            raise AwsCliError(f"{rendered} failed: {error}")
        try:
            value = json.loads(completed.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise AwsCliError(f"AWS CLI returned non-JSON for {' '.join(args)}") from exc
        if not isinstance(value, dict):
            raise AwsCliError(f"AWS CLI returned a non-object for {' '.join(args)}")
        return value


def _statements(document: Any) -> list[dict[str, Any]]:
    """Normalise a Lambda policy document or GetPolicy result."""
    if document is None:
        return []
    if isinstance(document, Mapping) and "Policy" in document:
        document = document["Policy"]
    if isinstance(document, str):
        try:
            document = json.loads(document)
        except json.JSONDecodeError:
            return []
    if not isinstance(document, Mapping):
        return []
    raw = document.get("Statement", [])
    if isinstance(raw, Mapping):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    return [dict(statement) for statement in raw if isinstance(statement, Mapping)]


def _values(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return {item for item in value if isinstance(item, str)}
    return set()


def _source_arns(statement: Mapping[str, Any]) -> set[str]:
    found: set[str] = set()
    condition = statement.get("Condition")
    if not isinstance(condition, Mapping):
        return found
    for entries in condition.values():
        if not isinstance(entries, Mapping):
            continue
        for key, value in entries.items():
            if str(key).lower() == "aws:sourcearn":
                found.update(_values(value))
    return found


def _source_account_conditions(
    statement: Mapping[str, Any],
) -> list[tuple[str, set[str]]]:
    found: list[tuple[str, set[str]]] = []
    condition = statement.get("Condition")
    if not isinstance(condition, Mapping):
        return found
    for operator, entries in condition.items():
        if not isinstance(entries, Mapping):
            continue
        for key, value in entries.items():
            if str(key).lower() == "aws:sourceaccount":
                found.append((str(operator), _values(value)))
    return found


def _permission_findings(
    expected: ExpectedFunction,
    statement: Mapping[str, Any],
) -> list[Finding]:
    out: list[Finding] = []
    subject = expected.name
    if statement.get("Effect") != "Allow":
        out.append(Finding("permission-effect", subject, "expected Effect Allow"))
    if _values(statement.get("Action")) != {"lambda:InvokeFunction"}:
        out.append(
            Finding(
                "permission-action",
                subject,
                "permission must grant only lambda:InvokeFunction",
            )
        )
    if statement.get("Principal") != API_GATEWAY_PRINCIPAL:
        out.append(
            Finding(
                "permission-principal",
                subject,
                "permission principal must be only apigateway.amazonaws.com",
            )
        )
    if statement.get("Resource") != expected.alias_arn:
        out.append(
            Finding(
                "permission-resource",
                subject,
                f"permission Resource must be the live alias {expected.alias_arn}",
            )
        )
    if expected.source_arn is not None and _source_arns(statement) != {expected.source_arn}:
        out.append(
            Finding(
                "permission-source",
                subject,
                f"AWS:SourceArn must be exactly {expected.source_arn}",
            )
        )
    if (
        expected.source_account is not None
        and _source_account_conditions(statement)
        != [("StringEquals", {expected.source_account})]
    ):
        out.append(
            Finding(
                "permission-source-account",
                subject,
                "one StringEquals/AWS:SourceAccount condition must name exactly "
                f"{expected.source_account}",
            )
        )
    return out


def _function_name_from_arn(value: Any) -> str | None:
    if not isinstance(value, str) or ":function:" not in value:
        return None
    return value.split(":function:", 1)[1].split(":", 1)[0]


def _valid_hostname(value: str) -> bool:
    if value != value.lower() or len(value) > 253:
        return False
    labels = value.split(".")
    return bool(labels) and all(
        label
        and len(label) <= 63
        and _HOST_LABEL.fullmatch(label) is not None
        for label in labels
    )


def _parse_expected_vpc_config_json(value: str) -> ExpectedVpcConfig:
    """Parse the non-sensitive canonical Terraform VPC output strictly."""
    try:
        document = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError("expected VPC configuration is not valid JSON") from exc
    required_keys = {
        "vpc_id",
        "vpc_ipv4_cidr",
        "subnet_ids",
        "security_group_ids",
    }
    if not isinstance(document, Mapping) or set(document) != required_keys:
        raise ValueError(
            "expected VPC configuration must contain exactly vpc_id, "
            "vpc_ipv4_cidr, subnet_ids, and security_group_ids"
        )

    vpc_id = document.get("vpc_id")
    vpc_ipv4_cidr = document.get("vpc_ipv4_cidr")
    subnet_ids = document.get("subnet_ids")
    security_group_ids = document.get("security_group_ids")
    if not isinstance(vpc_id, str) or _VPC_ID.fullmatch(vpc_id) is None:
        raise ValueError("expected VPC configuration has an invalid vpc_id")
    if not isinstance(vpc_ipv4_cidr, str):
        raise ValueError(
            "expected VPC configuration has an invalid canonical vpc_ipv4_cidr"
        )
    try:
        vpc_network = ipaddress.ip_network(vpc_ipv4_cidr, strict=True)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "expected VPC configuration has an invalid canonical vpc_ipv4_cidr"
        ) from exc
    if vpc_network.version != 4:
        raise ValueError(
            "expected VPC configuration has an invalid canonical vpc_ipv4_cidr"
        )
    if (
        not isinstance(subnet_ids, list)
        or len(subnet_ids) < 2
        or any(
            not isinstance(item, str) or _SUBNET_ID.fullmatch(item) is None
            for item in subnet_ids
        )
        or len(subnet_ids) != len(set(subnet_ids))
    ):
        raise ValueError(
            "expected VPC configuration must have at least two unique subnet ids"
        )
    if (
        not isinstance(security_group_ids, list)
        or not security_group_ids
        or any(
            not isinstance(item, str) or _SECURITY_GROUP_ID.fullmatch(item) is None
            for item in security_group_ids
        )
        or len(security_group_ids) != len(set(security_group_ids))
    ):
        raise ValueError(
            "expected VPC configuration must have unique security group ids"
        )
    return ExpectedVpcConfig(
        vpc_id=vpc_id,
        vpc_ipv4_cidr=str(vpc_network),
        subnet_ids=frozenset(subnet_ids),
        security_group_ids=frozenset(security_group_ids),
    )


def _parse_route_roles(value: Any) -> dict[str, frozenset[str]]:
    """Parse API_ROUTE_ROLES strictly without ever including its value in errors."""
    if not isinstance(value, str):
        raise ValueError("API_ROUTE_ROLES is absent")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        parsed: dict[str, Any] = {}
        for key, item in pairs:
            if key in parsed:
                raise ValueError("API_ROUTE_ROLES contains a duplicate route key")
            parsed[key] = item
        return parsed

    try:
        document = json.loads(value, object_pairs_hook=unique_object)
    except json.JSONDecodeError as exc:
        raise ValueError("API_ROUTE_ROLES is not valid JSON") from exc
    if not isinstance(document, Mapping):
        raise ValueError("API_ROUTE_ROLES is not an object")

    result: dict[str, frozenset[str]] = {}
    for route_key, roles in document.items():
        if (
            not isinstance(route_key, str)
            or not route_key
            or route_key.strip() != route_key
        ):
            raise ValueError("API_ROUTE_ROLES has an invalid route key")
        if not isinstance(roles, list):
            raise ValueError("API_ROUTE_ROLES has a non-array role list")
        if any(
            not isinstance(role, str) or not role or role.strip() != role
            for role in roles
        ):
            raise ValueError("API_ROUTE_ROLES has an invalid role")
        if len(roles) != len(set(roles)):
            raise ValueError("API_ROUTE_ROLES has a duplicate role")
        result[route_key] = frozenset(roles)
    return result


def _integration_targets_alias(value: Any, expected: ExpectedFunction) -> bool:
    """Accept the two AWS representations that identify the same live alias."""
    return isinstance(value, str) and value in {
        expected.alias_arn,
        expected.integration_uri,
    }


def _custom_domain_findings(
    inventory: Mapping[str, Any],
    *,
    allowed_host: str,
    allow_absent: bool,
    enforce_account_singleton: bool = True,
) -> list[Finding]:
    api_id = str(inventory.get("api_id") or "api")
    raw_domain_names = inventory.get("api_domain_names")
    if not isinstance(raw_domain_names, list) or any(
        not isinstance(name, str) or not name for name in raw_domain_names
    ):
        return [
            Finding(
                "api-domain-count",
                api_id,
                "the account/Region custom-domain inventory is unavailable or malformed",
            )
        ]

    domain_names = sorted(raw_domain_names)
    matching_domain_names = [
        name for name in domain_names if name == allowed_host
    ]
    domain_inventory_matches = (
        domain_names == [allowed_host]
        if enforce_account_singleton
        else matching_domain_names == [allowed_host]
    )
    if not domain_inventory_matches:
        if allow_absent and not matching_domain_names and (
            not enforce_account_singleton or not domain_names
        ):
            return []
        scope = "the account and Region" if enforce_account_singleton else "this API"
        return [
            Finding(
                "api-domain-count",
                api_id,
                f"{scope} must contain exactly one API Gateway custom domain "
                f"named {allowed_host}; found {len(matching_domain_names)} matching "
                f"domain(s) among {len(domain_names)} total",
            )
        ]

    raw_domain_configurations = inventory.get("api_domain_configurations")
    if not isinstance(raw_domain_configurations, list) or any(
        not isinstance(domain, Mapping) for domain in raw_domain_configurations
    ):
        return [
            Finding(
                "api-domain-configuration",
                api_id,
                "the API custom-domain endpoint inventory is unavailable or malformed",
            )
        ]
    matching_configurations = [
        domain
        for domain in raw_domain_configurations
        if domain.get("DomainName") == allowed_host
    ]
    endpoint_configurations = (
        matching_configurations[0].get("DomainNameConfigurations")
        if len(matching_configurations) == 1
        else None
    )
    correct_endpoint = (
        isinstance(endpoint_configurations, list)
        and len(endpoint_configurations) == 1
        and isinstance(endpoint_configurations[0], Mapping)
        and endpoint_configurations[0].get("EndpointType") == "REGIONAL"
        and endpoint_configurations[0].get("SecurityPolicy") == "TLS_1_2"
        and endpoint_configurations[0].get("DomainNameStatus") == "AVAILABLE"
    )
    if not correct_endpoint:
        return [
            Finding(
                "api-domain-configuration",
                api_id,
                f"{allowed_host} must have exactly one AVAILABLE REGIONAL "
                "TLS_1_2 endpoint before an HTTP API can use it",
            )
        ]

    # API Gateway reports equivalent names through its two control planes.
    # Both values mean that routing rules are disabled and API mappings are
    # the sole routing mechanism. HTTP/WebSocket APIs cannot be mapped while
    # either routing-rule mode is enabled.
    routing_mode = matching_configurations[0].get("RoutingMode")
    if routing_mode not in {"API_MAPPING_ONLY", "BASE_PATH_MAPPING_ONLY"}:
        return [
            Finding(
                "api-domain-routing-mode",
                api_id,
                f"{allowed_host} must use mapping-only routing mode "
                "(API_MAPPING_ONLY/BASE_PATH_MAPPING_ONLY) before an HTTP API "
                f"can use it; found {routing_mode!r}",
            )
        ]

    raw_mappings = inventory.get("api_mappings")
    if not isinstance(raw_mappings, list) or any(
        not isinstance(mapping, Mapping) for mapping in raw_mappings
    ):
        return [
            Finding(
                "api-domain-mapping",
                api_id,
                "the API custom-domain mapping inventory is unavailable or malformed",
            )
        ]
    relevant_mappings = (
        raw_mappings
        if enforce_account_singleton
        else [
            mapping
            for mapping in raw_mappings
            if mapping.get("DomainName") == allowed_host
        ]
    )
    if allow_absent and not relevant_mappings:
        return []

    correct_mapping = (
        len(relevant_mappings) == 1
        and relevant_mappings[0].get("DomainName") == allowed_host
        and relevant_mappings[0].get("ApiId") == inventory.get("api_id")
        and relevant_mappings[0].get("Stage") == "$default"
        and relevant_mappings[0].get("ApiMappingKey") in (None, "")
    )
    if correct_mapping:
        return []
    return [
        Finding(
            "api-domain-mapping",
            api_id,
            "the sole custom domain must have exactly one root mapping to this "
            "API/$default and no other API mapping",
        )
    ]


def _gateway_boundary_findings(
    inventory: Mapping[str, Any],
    *,
    allowed_host: str,
    enforce_custom_domain_singleton: bool = True,
) -> list[Finding]:
    findings: list[Finding] = []
    api_id = str(inventory.get("api_id") or "api")
    api = inventory.get("api")
    if not isinstance(api, Mapping):
        findings.append(
            Finding("api-configuration", api_id, "the supplied API could not be read")
        )
    else:
        if api.get("ApiId") != inventory.get("api_id"):
            findings.append(
                Finding(
                    "api-configuration",
                    api_id,
                    "get-api did not return the supplied API id",
                )
            )
        if api.get("ProtocolType") != "HTTP":
            findings.append(
                Finding("api-protocol", api_id, "the surviving API must be HTTP")
            )
        if api.get("DisableExecuteApiEndpoint") is not True:
            findings.append(
                Finding(
                    "api-default-endpoint",
                    api_id,
                    "the default execute-api endpoint must be disabled",
                )
            )

    stages = inventory.get("api_stages") or []
    if not isinstance(stages, list):
        stages = []
    default_stages = [
        stage
        for stage in stages
        if isinstance(stage, Mapping) and stage.get("StageName") == "$default"
    ]
    if len(stages) != 1 or len(default_stages) != 1:
        findings.append(
            Finding(
                "api-stages",
                api_id,
                "the API must have exactly one stage named $default",
            )
        )
    elif default_stages[0].get("AutoDeploy") is not True:
        findings.append(
            Finding(
                "api-stage-autodeploy",
                api_id,
                "the $default stage must have AutoDeploy enabled",
            )
        )

    findings.extend(
        _custom_domain_findings(
            inventory,
            allowed_host=allowed_host,
            allow_absent=False,
            enforce_account_singleton=enforce_custom_domain_singleton,
        )
    )
    return findings


def _route_contract_findings(
    expected: Mapping[str, ExpectedFunction],
    inventory: Mapping[str, Any],
    *,
    authorizer_id: str | None,
) -> list[Finding]:
    findings: list[Finding] = []
    expected_routes = {
        item.route_key: item
        for item in expected.values()
        if item.kind == "route" and item.route_key is not None
    }
    protected_routes = {
        key: item
        for key, item in expected_routes.items()
        if item.authentication_required
    }
    if len(expected_routes) != EXPECTED_ROUTE_COUNT:
        findings.append(
            Finding(
                "manifest-route-count",
                "routes.yaml",
                f"expected exactly {EXPECTED_ROUTE_COUNT} HTTP routes; "
                f"found {len(expected_routes)}",
            )
        )
    if len(protected_routes) != EXPECTED_PROTECTED_ROUTE_COUNT:
        findings.append(
            Finding(
                "manifest-protected-route-count",
                "routes.yaml",
                f"expected exactly {EXPECTED_PROTECTED_ROUTE_COUNT} protected routes; "
                f"found {len(protected_routes)}",
            )
        )

    route_items = inventory.get("api_routes") or []
    if not isinstance(route_items, list):
        route_items = []
    routes: dict[str, Mapping[str, Any]] = {}
    malformed_routes = 0
    for item in route_items:
        if not isinstance(item, Mapping) or not isinstance(item.get("RouteKey"), str):
            malformed_routes += 1
            continue
        route_key = str(item["RouteKey"])
        if route_key in routes:
            malformed_routes += 1
            continue
        routes[route_key] = item
    if malformed_routes:
        findings.append(
            Finding(
                "api-route-inventory",
                str(inventory.get("api_id") or "api"),
                f"found {malformed_routes} malformed or duplicate route record(s)",
            )
        )
    if len(route_items) != EXPECTED_ROUTE_COUNT:
        findings.append(
            Finding(
                "api-route-count",
                str(inventory.get("api_id") or "api"),
                f"expected exactly {EXPECTED_ROUTE_COUNT} API route records; "
                f"found {len(route_items)}",
            )
        )
    expected_keys = set(expected_routes)
    actual_keys = set(routes)
    if actual_keys != expected_keys:
        findings.append(
            Finding(
                "api-route-set",
                str(inventory.get("api_id") or "api"),
                f"route keys differ from routes.yaml: "
                f"{len(expected_keys - actual_keys)} missing, "
                f"{len(actual_keys - expected_keys)} unexpected",
            )
        )

    integration_items = inventory.get("api_integrations") or []
    if not isinstance(integration_items, list):
        integration_items = []
    integrations: dict[str, Mapping[str, Any]] = {}
    malformed_integrations = 0
    for item in integration_items:
        if (
            not isinstance(item, Mapping)
            or not isinstance(item.get("IntegrationId"), str)
        ):
            malformed_integrations += 1
            continue
        integration_id = str(item["IntegrationId"])
        if integration_id in integrations:
            malformed_integrations += 1
            continue
        integrations[integration_id] = item
    if malformed_integrations:
        findings.append(
            Finding(
                "api-integration-inventory",
                str(inventory.get("api_id") or "api"),
                f"found {malformed_integrations} malformed or duplicate "
                "integration record(s)",
            )
        )
    if len(integration_items) != EXPECTED_ROUTE_COUNT:
        findings.append(
            Finding(
                "api-integration-count",
                str(inventory.get("api_id") or "api"),
                f"expected exactly {EXPECTED_ROUTE_COUNT} API integrations; "
                f"found {len(integration_items)}",
            )
        )

    referenced_integrations: set[str] = set()
    for route in routes.values():
        target = route.get("Target")
        if isinstance(target, str) and target.startswith("integrations/"):
            integration_id = target.removeprefix("integrations/")
            if integration_id and "/" not in integration_id:
                referenced_integrations.add(integration_id)
    if set(integrations) != referenced_integrations:
        findings.append(
            Finding(
                "api-integration-set",
                str(inventory.get("api_id") or "api"),
                "API integrations must be referenced one-for-one by the route set",
            )
        )

    for route_key in sorted(expected_keys & actual_keys):
        wanted = expected_routes[route_key]
        route = routes[route_key]
        if wanted.authentication_required:
            correctly_authorized = (
                isinstance(authorizer_id, str)
                and route.get("AuthorizationType") == "CUSTOM"
                and route.get("AuthorizerId") == authorizer_id
            )
            if not correctly_authorized:
                findings.append(
                    Finding(
                        "route-authorization",
                        route_key,
                        "protected route must use CUSTOM with only portal_jwt",
                    )
                )
        elif (
            route.get("AuthorizationType") != "NONE"
            or route.get("AuthorizerId") not in (None, "")
        ):
            findings.append(
                Finding(
                    "route-authorization",
                    route_key,
                    "public route must use NONE with no authorizer id",
                )
            )

        target = route.get("Target")
        if not isinstance(target, str) or not target.startswith("integrations/"):
            findings.append(
                Finding(
                    "route-target",
                    route_key,
                    "route target is not an API Gateway integration",
                )
            )
            continue
        integration_id = target.removeprefix("integrations/")
        if not integration_id or "/" in integration_id:
            findings.append(
                Finding("route-target", route_key, "route target is malformed")
            )
            continue
        integration = integrations.get(integration_id)
        if integration is None:
            findings.append(
                Finding(
                    "route-target",
                    route_key,
                    "route target names an integration that is absent",
                )
            )
            continue
        if integration.get("IntegrationType") != "AWS_PROXY":
            findings.append(
                Finding(
                    "integration-type",
                    route_key,
                    "route integration must be AWS_PROXY",
                )
            )
        if integration.get("PayloadFormatVersion") != "2.0":
            findings.append(
                Finding(
                    "integration-payload",
                    route_key,
                    "route integration must use payload format 2.0",
                )
            )
        if not _integration_targets_alias(integration.get("IntegrationUri"), wanted):
            findings.append(
                Finding(
                    "integration-target",
                    route_key,
                    "route integration must target its expected live Lambda alias",
                )
            )
    return findings


def _authorizer_configuration_findings(
    expected: Mapping[str, ExpectedFunction],
    authorizers: Sequence[Any],
) -> list[Finding]:
    wanted_items = [item for item in expected.values() if item.kind == "authorizer"]
    live_items = [
        item
        for item in authorizers
        if isinstance(item, Mapping) and item.get("Name") == "portal_jwt"
    ]
    if len(wanted_items) != 1 or len(authorizers) != 1 or len(live_items) != 1:
        return []
    wanted = wanted_items[0]
    actual = live_items[0]
    findings: list[Finding] = []
    actual_identity_sources = actual.get("IdentitySource")
    identity_sources_match = (
        isinstance(actual_identity_sources, list)
        and all(isinstance(source, str) for source in actual_identity_sources)
        and len(actual_identity_sources) == len(set(actual_identity_sources))
        and frozenset(actual_identity_sources) == frozenset(wanted.identity_sources)
    )
    checks = (
        (
            "authorizer-type",
            actual.get("AuthorizerType") == "REQUEST",
            "portal_jwt must be a REQUEST authorizer",
        ),
        (
            "authorizer-payload",
            actual.get("AuthorizerPayloadFormatVersion") == "2.0",
            "portal_jwt must use payload format 2.0",
        ),
        (
            "authorizer-simple-response",
            actual.get("EnableSimpleResponses") is True,
            "portal_jwt must use simple responses",
        ),
        (
            "authorizer-ttl",
            actual.get("AuthorizerResultTtlInSeconds") == wanted.authorizer_ttl == 0,
            "portal_jwt result caching must be disabled",
        ),
        (
            "authorizer-identity-sources",
            identity_sources_match,
            "portal_jwt identity sources must exactly match routes.yaml",
        ),
        (
            "authorizer-target",
            _integration_targets_alias(actual.get("AuthorizerUri"), wanted),
            "portal_jwt must target its expected live Lambda alias",
        ),
    )
    for code, passed, detail in checks:
        if not passed:
            findings.append(Finding(code, wanted.name, detail))
    return findings


def _function_configuration_findings(
    expected: Mapping[str, ExpectedFunction],
    inventory: Mapping[str, Any],
) -> list[Finding]:
    """Verify immutable live-version facts without retrieving unrelated settings."""
    findings: list[Finding] = []
    functions = inventory.get("functions") or {}
    if not isinstance(functions, Mapping):
        return findings
    for wanted in expected.values():
        raw = functions.get(wanted.name)
        if not isinstance(raw, Mapping):
            continue
        selected = raw.get("selected_environment")
        if not isinstance(selected, Mapping):
            findings.append(
                Finding(
                    "function-configuration",
                    wanted.name,
                    "selected live-alias configuration could not be read",
                )
            )
            continue
        checks = (
            (
                "function-runtime",
                selected.get("Runtime") == wanted.runtime == "python3.13",
                "live alias must run on Python 3.13",
            ),
            (
                "function-role",
                selected.get("Role") == wanted.role_arn,
                "live alias execution role does not match its manifest IAM profile",
            ),
            (
                "function-handler",
                selected.get("Handler") == wanted.handler,
                "live alias handler does not match routes.yaml",
            ),
        )
        for code, passed, detail in checks:
            if not passed:
                findings.append(Finding(code, wanted.name, detail))
    return findings


def _vpc_configuration_findings(
    expected: Mapping[str, ExpectedFunction],
    inventory: Mapping[str, Any],
    *,
    expected_vpc_config: ExpectedVpcConfig,
) -> list[Finding]:
    """Require the exact reviewed VPC attachment on all 49 live aliases."""
    findings: list[Finding] = []
    functions = inventory.get("functions") or {}
    if not isinstance(functions, Mapping):
        return findings

    for wanted in expected.values():
        raw = functions.get(wanted.name)
        selected = raw.get("selected_environment") if isinstance(raw, Mapping) else None
        if not isinstance(selected, Mapping):
            continue
        actual = selected.get("VpcConfig")
        if not isinstance(actual, Mapping):
            findings.append(
                Finding(
                    "function-vpc-configuration",
                    wanted.name,
                    "selected live alias has no readable VPC configuration",
                )
            )
            continue

        if actual.get("VpcId") != expected_vpc_config.vpc_id:
            findings.append(
                Finding(
                    "function-vpc-id",
                    wanted.name,
                    "live alias VPC does not match the canonical Terraform output",
                )
            )

        subnet_ids = actual.get("SubnetIds")
        actual_subnets = (
            frozenset(subnet_ids)
            if isinstance(subnet_ids, list)
            and all(isinstance(item, str) for item in subnet_ids)
            else None
        )
        if actual_subnets != expected_vpc_config.subnet_ids:
            findings.append(
                Finding(
                    "function-vpc-subnets",
                    wanted.name,
                    "live alias subnet set does not match the canonical Terraform output",
                )
            )

        security_group_ids = actual.get("SecurityGroupIds")
        actual_security_groups = (
            frozenset(security_group_ids)
            if isinstance(security_group_ids, list)
            and all(isinstance(item, str) for item in security_group_ids)
            else None
        )
        if actual_security_groups != expected_vpc_config.security_group_ids:
            findings.append(
                Finding(
                    "function-vpc-security-groups",
                    wanted.name,
                    "live alias security-group set does not match the canonical "
                    "Terraform output",
                )
            )
        if actual.get("Ipv6AllowedForDualStack") is not False:
            findings.append(
                Finding(
                    "function-vpc-ipv6",
                    wanted.name,
                    "live alias must have dual-stack IPv6 egress disabled",
                )
            )
    return findings


def _environment_contract_findings(
    expected: Mapping[str, ExpectedFunction],
    inventory: Mapping[str, Any],
    *,
    allowed_host: str,
) -> list[Finding]:
    findings: list[Finding] = []
    functions = inventory.get("functions") or {}
    if not isinstance(functions, Mapping):
        return findings

    for wanted in expected.values():
        if wanted.kind != "route" or wanted.name not in functions:
            continue
        raw = functions[wanted.name]
        selected = raw.get("selected_environment") if isinstance(raw, Mapping) else None
        if not isinstance(selected, Mapping):
            findings.append(
                Finding(
                    "route-environment",
                    wanted.name,
                    "selected live-alias environment could not be read",
                )
            )
            continue
        if selected.get("UID_RUNTIME") != "aws":
            findings.append(
                Finding(
                    "route-runtime-mode",
                    wanted.name,
                    "UID_RUNTIME must be aws on the live alias",
                )
            )
        if selected.get("DEV_AUTH_BYPASS") not in (None, "false"):
            findings.append(
                Finding(
                    "route-dev-auth-bypass",
                    wanted.name,
                    "DEV_AUTH_BYPASS must be absent or false on the live alias",
                )
            )
        expected_authentication = (
            "true" if wanted.authentication_required else "false"
        )
        if selected.get("REQUIRE_AUTHENTICATION") != expected_authentication:
            findings.append(
                Finding(
                    "route-require-authentication",
                    wanted.name,
                    "REQUIRE_AUTHENTICATION does not match routes.yaml",
                )
            )
        if selected.get("REQUIRED_ROLES") != ",".join(wanted.roles):
            findings.append(
                Finding(
                    "route-required-roles",
                    wanted.name,
                    "REQUIRED_ROLES does not match routes.yaml",
                )
            )
        raw_route_hosts = selected.get("API_ALLOWED_HOSTS")
        route_hosts = (
            [item.strip() for item in raw_route_hosts.split(",") if item.strip()]
            if isinstance(raw_route_hosts, str)
            else []
        )
        if route_hosts != [allowed_host]:
            findings.append(
                Finding(
                    "route-allowed-hosts",
                    wanted.name,
                    "API_ALLOWED_HOSTS must contain only the required allowed host",
                )
            )

    expected_authorizers = [
        item for item in expected.values() if item.kind == "authorizer"
    ]
    if len(expected_authorizers) != 1:
        return findings
    wanted_authorizer = expected_authorizers[0]
    raw_authorizer = functions.get(wanted_authorizer.name)
    selected = (
        raw_authorizer.get("selected_environment")
        if isinstance(raw_authorizer, Mapping)
        else None
    )
    if not isinstance(selected, Mapping):
        findings.append(
            Finding(
                "authorizer-environment",
                wanted_authorizer.name,
                "selected live-alias environment could not be read",
            )
        )
        return findings
    if selected.get("UID_RUNTIME") != "aws":
        findings.append(
            Finding(
                "authorizer-runtime-mode",
                wanted_authorizer.name,
                "UID_RUNTIME must be aws on the live alias",
            )
        )
    if selected.get("DEV_AUTH_BYPASS") not in (None, "false"):
        findings.append(
            Finding(
                "authorizer-dev-auth-bypass",
                wanted_authorizer.name,
                "DEV_AUTH_BYPASS must be absent or false on the live alias",
            )
        )

    protected_roles = {
        item.route_key: frozenset(item.roles)
        for item in expected.values()
        if item.kind == "route"
        and item.authentication_required
        and item.route_key is not None
    }
    try:
        actual_roles = _parse_route_roles(selected.get("API_ROUTE_ROLES"))
    except ValueError:
        actual_roles = None
    if actual_roles != protected_roles or len(protected_roles) != EXPECTED_PROTECTED_ROUTE_COUNT:
        findings.append(
            Finding(
                "authorizer-route-roles",
                wanted_authorizer.name,
                "API_ROUTE_ROLES must semantically match all 38 protected routes",
            )
        )

    raw_hosts = selected.get("API_ALLOWED_HOSTS")
    hosts = (
        [item.strip() for item in raw_hosts.split(",") if item.strip()]
        if isinstance(raw_hosts, str)
        else []
    )
    if hosts != [allowed_host]:
        findings.append(
            Finding(
                "authorizer-allowed-hosts",
                wanted_authorizer.name,
                "API_ALLOWED_HOSTS must contain only the required allowed host",
            )
        )

    # These checks intentionally inspect only the authorizer. Route Lambdas do
    # not consume the access-token contract, and duplicating it there would
    # increase both environment size and the surface for configuration drift.
    oidc_checks = (
        (
            "authorizer-oidc-issuer",
            selected.get("OIDC_ISSUER") == PING_ISSUER,
            "OIDC_ISSUER must be the exact approved Ping issuer",
        ),
        (
            "authorizer-oidc-jwks",
            selected.get("OIDC_JWKS_URL") in ("", PING_JWKS_URL),
            "OIDC_JWKS_URL must be empty (derive it from Ping) or the exact "
            "approved Ping JWKS URL",
        ),
        (
            "authorizer-oidc-audience",
            selected.get("OIDC_AUDIENCE") == PING_AUDIENCE,
            "OIDC_AUDIENCE must exactly match the approved shared Ping audience",
        ),
        (
            "authorizer-oidc-utah-id-claim",
            selected.get("OIDC_UTAH_ID_CLAIM") == "legacy_sub",
            "OIDC_UTAH_ID_CLAIM must be exactly legacy_sub",
        ),
    )
    for code, passed, detail in oidc_checks:
        if not passed:
            findings.append(Finding(code, wanted_authorizer.name, detail))

    raw_scopes = selected.get("OIDC_REQUIRED_SCOPES")
    scopes = raw_scopes.split() if isinstance(raw_scopes, str) else []
    contract_checks = (
        (
            "authorizer-oidc-scope-claim",
            selected.get("OIDC_SCOPE_CLAIM") == PING_SCOPE_CLAIM,
            "OIDC_SCOPE_CLAIM must exactly match the approved Ping scope claim",
        ),
        (
            "authorizer-oidc-required-scopes",
            len(scopes) == len(PING_REQUIRED_SCOPES)
            and frozenset(scopes) == PING_REQUIRED_SCOPES,
            "OIDC_REQUIRED_SCOPES must exactly match the approved Ping scope set",
        ),
        (
            "authorizer-oidc-authorized-party-claim",
            selected.get("OIDC_AUTHORIZED_PARTY_CLAIM")
            == PING_AUTHORIZED_PARTY_CLAIM,
            "OIDC_AUTHORIZED_PARTY_CLAIM must exactly match the approved Ping claim",
        ),
        (
            "authorizer-oidc-authorized-party-value",
            selected.get("OIDC_AUTHORIZED_PARTY_VALUE")
            == PING_AUTHORIZED_PARTY_VALUE,
            "OIDC_AUTHORIZED_PARTY_VALUE must exactly match the approved Ping client",
        ),
        (
            "authorizer-oidc-token-type-source",
            selected.get("OIDC_TOKEN_TYPE_SOURCE") == PING_TOKEN_TYPE_SOURCE,
            "OIDC_TOKEN_TYPE_SOURCE must exactly match the approved Ping source",
        ),
        (
            "authorizer-oidc-token-type-name",
            selected.get("OIDC_TOKEN_TYPE_NAME") == PING_TOKEN_TYPE_NAME,
            "OIDC_TOKEN_TYPE_NAME must exactly match the approved Ping field",
        ),
        (
            "authorizer-oidc-token-type-value",
            selected.get("OIDC_TOKEN_TYPE_VALUE") == PING_TOKEN_TYPE_VALUE,
            "OIDC_TOKEN_TYPE_VALUE must exactly match the approved Ping access-token type",
        ),
    )
    for code, passed, detail in contract_checks:
        if not passed:
            findings.append(Finding(code, wanted_authorizer.name, detail))
    return findings


def _managed_apis(
    inventory: Mapping[str, Any], expected_api_name: str | None = None
) -> list[Mapping[str, Any]]:
    """Identify this application's APIs without treating every regional API as ours."""
    account_apis = inventory.get("apis") or []
    if not isinstance(account_apis, list):
        return []
    managed: list[Mapping[str, Any]] = []
    for api in account_apis:
        if not isinstance(api, Mapping):
            continue
        name = str(api.get("Name") or "")
        tags = api.get("Tags") or {}
        tagged = isinstance(tags, Mapping) and tags.get("Application") == "uid-portal-api"
        historical = bool(
            re.fullmatch(
                r"(?:uid-portal-(?:dev|at|prod)-(?:portal|licensee)"
                r"|uid-(?:dev|prod)-api-gateway)",
                name,
            )
        )
        if tagged or historical or (expected_api_name and name == expected_api_name):
            managed.append(api)
    return managed


def audit_api_cardinality(
    inventory: Mapping[str, Any],
    *,
    expected_api_id: str | None = None,
    expected_api_name: str | None = None,
) -> list[Finding]:
    """Check target-account-and-Region cardinality for deploy-time gates."""
    managed_apis = _managed_apis(inventory, expected_api_name)
    expected_survivor = bool(expected_api_id or expected_api_name)
    # No state identity means this must be a genuinely fresh account: allowing
    # one unknown API here could let Terraform create a second one. Once state
    # supplies a survivor, require exactly that one live resource instead.
    acceptable_counts = {1} if expected_survivor else {0}
    if len(managed_apis) not in acceptable_counts:
        rendered = ", ".join(
            sorted(
                f"{api.get('ApiId', '?')}:{api.get('Name', '?')}"
                for api in managed_apis
            )
        ) or "none"
        expectation = "exactly one" if acceptable_counts == {1} else "zero"
        return [
            Finding(
                "api-count",
                str(inventory.get("account_id") or "account"),
                f"expected {expectation} UID Portal HTTP API in the target "
                f"account and Region; "
                f"found {len(managed_apis)} ({rendered})",
            )
        ]
    if not managed_apis:
        return []

    survivor = managed_apis[0]
    if (
        expected_api_id is not None
        and survivor.get("ApiId") != expected_api_id
    ) or (
        expected_api_name is not None
        and survivor.get("Name") != expected_api_name
    ):
        return [
            Finding(
                "api-identity",
                str(expected_api_id or "terraform survivor"),
                "the one live API does not match the supplied Terraform survivor",
            )
        ]
    return []


def audit_inventory(
    expected: Mapping[str, ExpectedFunction],
    inventory: Mapping[str, Any],
    *,
    function_prefix: str,
    expected_api_name: str,
    allowed_host: str,
    expected_vpc_config: ExpectedVpcConfig,
    authorizer_name: str = "portal_jwt",
    enforce_custom_domain_singleton: bool = True,
) -> list[Finding]:
    """Return every live-state violation in a normalised inventory."""
    findings: list[Finding] = []

    if len(expected) != EXPECTED_FUNCTION_COUNT:
        findings.append(
            Finding(
                "manifest-function-count",
                "routes.yaml",
                f"expected exactly {EXPECTED_FUNCTION_COUNT} functions; "
                f"found {len(expected)}",
            )
        )

    # API names themselves are not unique in AWS. Count both tagged resources
    # and historical UID names so a second state or stale shell API cannot hide
    # beside the supplied survivor id in this target account and Region.
    findings.extend(
        audit_api_cardinality(
            inventory,
            expected_api_id=str(inventory.get("api_id") or ""),
            expected_api_name=expected_api_name,
        )
    )

    functions = inventory.get("functions") or {}
    if not isinstance(functions, Mapping):
        functions = {}

    actual_names = set(str(name) for name in functions)
    expected_names = set(expected)
    for name in sorted(expected_names - actual_names):
        findings.append(Finding("missing-function", name, "manifest function is absent"))
    for name in sorted(actual_names - expected_names):
        findings.append(
            Finding(
                "unexpected-function",
                name,
                f"function has managed prefix {UID_PORTAL_FUNCTION_PREFIX} but is "
                "not in this environment's routes.yaml",
            )
        )

    # Alternate ingress is forbidden for every function carrying the managed
    # prefix, including a stale function that is no longer in the manifest.
    # Reporting both findings makes cleanup targets explicit without mutating
    # them or silently stopping at the manifest-drift finding.
    for name in sorted(actual_names):
        raw = functions[name]
        if not isinstance(raw, Mapping):
            continue
        for alias in raw.get("aliases") or []:
            if not isinstance(alias, Mapping) or alias.get("Name") != "live":
                continue
            routing = alias.get("RoutingConfig")
            weights = (
                routing.get("AdditionalVersionWeights")
                if isinstance(routing, Mapping)
                else None
            )
            if weights:
                findings.append(
                    Finding(
                        "live-alias-weighted-routing",
                        name,
                        "the live alias must point to one immutable version without "
                        "additional version weights",
                    )
                )
        urls = raw.get("function_urls") or []
        if urls:
            findings.append(
                Finding(
                    "function-url",
                    name,
                    f"found {len(urls)} Lambda function URL configuration(s)",
                )
            )
        mappings = raw.get("event_source_mappings") or []
        if mappings:
            findings.append(
                Finding(
                    "event-source-mapping",
                    name,
                    f"found {len(mappings)} event-source mapping(s)",
                )
            )
        if name not in expected_names:
            policies = raw.get("policies") or {}
            if isinstance(policies, Mapping):
                count = sum(len(_statements(document)) for document in policies.values())
                if count:
                    findings.append(
                        Finding(
                            "unexpected-function-policy",
                            name,
                            f"found {count} resource-policy statement(s) on an "
                            "unexpected function",
                        )
                    )

    authorizers = inventory.get("api_authorizers") or []
    if not isinstance(authorizers, list):
        authorizers = []
    matching_authorizers = [
        item for item in authorizers
        if isinstance(item, Mapping) and item.get("Name") == authorizer_name
    ]
    if len(authorizers) != 1 or len(matching_authorizers) != 1:
        findings.append(
            Finding(
                "api-authorizers",
                inventory.get("api_id", "api"),
                f"expected exactly one API authorizer named {authorizer_name}; "
                f"found {len(authorizers)}",
            )
        )
    sole_authorizer_id = (
        str(matching_authorizers[0].get("AuthorizerId"))
        if len(authorizers) == 1
        and len(matching_authorizers) == 1
        and matching_authorizers[0].get("AuthorizerId")
        else None
    )
    findings.extend(
        _gateway_boundary_findings(
            inventory,
            allowed_host=allowed_host,
            enforce_custom_domain_singleton=enforce_custom_domain_singleton,
        )
    )
    findings.extend(_authorizer_configuration_findings(expected, authorizers))
    findings.extend(
        _route_contract_findings(
            expected,
            inventory,
            authorizer_id=sole_authorizer_id,
        )
    )
    findings.extend(_function_configuration_findings(expected, inventory))
    findings.extend(
        _vpc_configuration_findings(
            expected,
            inventory,
            expected_vpc_config=expected_vpc_config,
        )
    )
    findings.extend(
        _environment_contract_findings(
            expected,
            inventory,
            allowed_host=allowed_host,
        )
    )

    for name in sorted(expected_names & actual_names):
        wanted = expected[name]
        raw = functions[name]
        if not isinstance(raw, Mapping):
            findings.append(Finding("function-inventory", name, "inventory entry is malformed"))
            continue

        aliases = {
            alias.get("Name")
            for alias in raw.get("aliases", [])
            if isinstance(alias, Mapping) and isinstance(alias.get("Name"), str)
        }
        if "live" not in aliases:
            findings.append(Finding("missing-live-alias", name, "live alias is absent"))

        policies = raw.get("policies") or {}
        if not isinstance(policies, Mapping):
            policies = {}
        live_statements = _statements(policies.get("alias:live"))
        if wanted.kind in {"route", "authorizer"}:
            if len(live_statements) != 1:
                findings.append(
                    Finding(
                        "live-permission-count",
                        name,
                        "expected exactly one live-alias API Gateway statement; "
                        f"found {len(live_statements)}",
                    )
                )
            if len(live_statements) == 1:
                findings.extend(_permission_findings(wanted, live_statements[0]))
        elif live_statements:
            findings.append(
                Finding(
                    "non-http-resource-policy",
                    name,
                    f"{wanted.kind} function must use identity-based invocation, "
                    "not a live resource policy",
                )
            )

        for scope, document in policies.items():
            if scope == "alias:live":
                continue
            count = len(_statements(document))
            if count:
                findings.append(
                    Finding(
                        "unexpected-policy-scope",
                        name,
                        f"found {count} resource-policy statement(s) at {scope}; "
                        "only alias:live is permitted for HTTP ingress",
                    )
                )

    for group in inventory.get("lambda_target_groups") or []:
        if not isinstance(group, Mapping):
            continue
        group_name = str(
            group.get("TargetGroupName")
            or group.get("TargetGroupArn")
            or "target-group"
        )
        targets = group.get("Targets") or []
        matching_targets = sorted(
            name
            for name in (_function_name_from_arn(target) for target in targets)
            if name and name.startswith(UID_PORTAL_FUNCTION_PREFIX)
        )
        if group_name.startswith(UID_PORTAL_FUNCTION_PREFIX) or matching_targets:
            detail = (
                "Lambda target group uses the managed prefix"
                if not matching_targets
                else f"Lambda target group registers: {', '.join(matching_targets)}"
            )
            findings.append(Finding("alb-lambda-target", group_name, detail))

    return findings


def _load_manifest(path: Path) -> dict[str, Any]:
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - exercised by the CLI environment
        raise RuntimeError(
            "PyYAML is required; install the existing services/api requirements"
        ) from exc
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"{path} is not a YAML object")
    return value


def build_expectations(
    manifest: Mapping[str, Any],
    *,
    env_name: str,
    region: str,
    account_id: str,
    api_id: str,
    authorizer_id: str | None,
) -> dict[str, ExpectedFunction]:
    apis = manifest.get("apis") or {}
    if not isinstance(apis, Mapping) or set(apis) != {"portal"}:
        raise RuntimeError("routes.yaml must declare exactly one API named portal")
    portal = apis["portal"]
    if not isinstance(portal, Mapping):
        raise RuntimeError("routes.yaml portal API is malformed")
    defaults = manifest.get("defaults") or {}
    if not isinstance(defaults, Mapping):
        raise RuntimeError("routes.yaml defaults are malformed")
    prefix = f"uid-portal-{env_name}-"
    base_arn = f"arn:aws:lambda:{region}:{account_id}:function:"
    execution_arn = f"arn:aws:execute-api:{region}:{account_id}:{api_id}"
    expected: dict[str, ExpectedFunction] = {}

    def add_expected(item: ExpectedFunction) -> None:
        if item.name in expected:
            raise RuntimeError(
                f"manifest function name {item.name!r} is declared more than once"
            )
        expected[item.name] = item

    def runtime_contract(
        definition: Mapping[str, Any], function_id: str
    ) -> tuple[str, str]:
        profile = definition.get("iam_profile")
        handler = definition.get("handler")
        if not isinstance(profile, str) or not profile:
            raise RuntimeError(f"function {function_id} has no IAM profile")
        if not isinstance(handler, str) or handler.count(":") != 1:
            raise RuntimeError(f"function {function_id} has an invalid handler")
        role_arn = f"arn:aws:iam::{account_id}:role/{prefix}{profile}"
        return role_arn, handler.replace(":", ".")

    for route in portal.get("routes") or []:
        if not isinstance(route, Mapping):
            continue
        function_id = str(route.get("id") or "")
        if not function_id:
            raise RuntimeError("route without id in routes.yaml")
        name = prefix + function_id
        role_arn, handler = runtime_contract(route, function_id)
        method = str(route.get("method") or "NONE").upper()
        path = route.get("path")
        if method == "NONE":
            kind = "worker"
            source_arn = None
            integration_uri = None
            route_key = None
            authentication_required = None
            roles: tuple[str, ...] = ()
        else:
            if not isinstance(path, str) or not path.startswith("/"):
                raise RuntimeError(f"HTTP route {function_id} has an invalid path")
            auth = str(route.get("auth") or "none").lower()
            if auth not in {"none", "jwt"}:
                raise RuntimeError(f"HTTP route {function_id} has an invalid auth mode")
            raw_roles = route.get("roles", defaults.get("roles", []))
            if (
                not isinstance(raw_roles, list)
                or any(
                    not isinstance(role, str)
                    or not role
                    or role.strip() != role
                    for role in raw_roles
                )
                or len(raw_roles) != len(set(raw_roles))
            ):
                raise RuntimeError(f"HTTP route {function_id} has invalid roles")
            kind = "route"
            permission_path = re.sub(r"\{[^}]+\}", "*", path)
            source_arn = f"{execution_arn}/*/{method}{permission_path}"
            alias_arn = f"{base_arn}{name}:live"
            integration_uri = (
                f"arn:aws:apigateway:{region}:lambda:path/2015-03-31/functions/"
                f"{alias_arn}/invocations"
            )
            route_key = f"{method} {path}"
            authentication_required = auth == "jwt"
            roles = tuple(raw_roles)
        add_expected(
            ExpectedFunction(
                function_id=function_id,
                name=name,
                kind=kind,
                alias_arn=f"{base_arn}{name}:live",
                source_arn=source_arn,
                source_account=account_id if kind == "route" else None,
                integration_uri=integration_uri,
                route_key=route_key,
                authentication_required=authentication_required,
                roles=roles,
                role_arn=role_arn,
                handler=handler,
            )
        )

    authorizer = portal.get("authorizer") or {}
    if not isinstance(authorizer, Mapping):
        raise RuntimeError("portal authorizer is malformed")
    function_id = str(authorizer.get("id") or "")
    if not function_id:
        raise RuntimeError("portal authorizer has no id")
    raw_identity_sources = authorizer.get("identity_sources") or []
    if (
        not isinstance(raw_identity_sources, list)
        or any(
            not isinstance(source, str) or not source
            for source in raw_identity_sources
        )
        or len(raw_identity_sources) != len(set(raw_identity_sources))
    ):
        raise RuntimeError("portal authorizer identity sources are malformed")
    try:
        authorizer_ttl = int(authorizer.get("ttl", 300))
    except (TypeError, ValueError) as exc:
        raise RuntimeError("portal authorizer TTL is malformed") from exc
    name = prefix + function_id
    role_arn, handler = runtime_contract(authorizer, function_id)
    alias_arn = f"{base_arn}{name}:live"
    add_expected(
        ExpectedFunction(
            function_id=function_id,
            name=name,
            kind="authorizer",
            alias_arn=alias_arn,
            source_arn=(
                f"{execution_arn}/authorizers/{authorizer_id}"
                if authorizer_id
                else None
            ),
            source_account=account_id,
            integration_uri=(
                f"arn:aws:apigateway:{region}:lambda:path/2015-03-31/functions/"
                f"{alias_arn}/invocations"
            ),
            identity_sources=tuple(raw_identity_sources),
            authorizer_ttl=authorizer_ttl,
            role_arn=role_arn,
            handler=handler,
        )
    )

    for schedule in manifest.get("scheduled") or []:
        if not isinstance(schedule, Mapping):
            continue
        function_id = str(schedule.get("id") or "")
        if not function_id:
            raise RuntimeError("schedule without id in routes.yaml")
        name = prefix + function_id
        role_arn, handler = runtime_contract(schedule, function_id)
        add_expected(
            ExpectedFunction(
                function_id=function_id,
                name=name,
                kind="schedule",
                alias_arn=f"{base_arn}{name}:live",
                role_arn=role_arn,
                handler=handler,
            )
        )
    return expected


def _policy(cli: AwsCli, function_name: str, qualifier: str | None = None) -> Any:
    args = ["lambda", "get-policy", "--function-name", function_name]
    if qualifier is not None:
        args.extend(["--qualifier", qualifier])
    result = cli.json(*args, missing_ok=True)
    return result.get("Policy") if result else None


def _collect_function(cli: AwsCli, function: Mapping[str, Any]) -> tuple[str, dict[str, Any]]:
    name = str(function["FunctionName"])
    aliases = cli.json("lambda", "list-aliases", "--function-name", name) or {}
    versions = cli.json("lambda", "list-versions-by-function", "--function-name", name) or {}
    urls = cli.json("lambda", "list-function-url-configs", "--function-name", name) or {}
    mappings = cli.json("lambda", "list-event-source-mappings", "--function-name", name) or {}

    alias_items = aliases.get("Aliases") or []
    version_items = versions.get("Versions") or []
    selected_environment = None
    if any(
        isinstance(alias, Mapping) and alias.get("Name") == "live"
        for alias in alias_items
    ):
        selected_environment = cli.json(
            "lambda",
            "get-function-configuration",
            "--function-name",
            name,
            "--qualifier",
            "live",
            "--query",
            _SELECTED_ENVIRONMENT_QUERY,
            missing_ok=True,
        )
    policies: dict[str, Any] = {"unqualified": _policy(cli, name)}
    for alias in alias_items:
        if isinstance(alias, Mapping) and alias.get("Name"):
            alias_name = str(alias["Name"])
            policies[f"alias:{alias_name}"] = _policy(cli, name, alias_name)
    for version in version_items:
        if isinstance(version, Mapping) and version.get("Version") not in (None, "$LATEST"):
            version_name = str(version["Version"])
            policies[f"version:{version_name}"] = _policy(cli, name, version_name)

    return name, {
        "function_arn": function.get("FunctionArn"),
        "aliases": alias_items,
        "versions": version_items,
        "function_urls": urls.get("FunctionUrlConfigs") or [],
        "event_source_mappings": mappings.get("EventSourceMappings") or [],
        "policies": policies,
        # The CLI projection retrieves only selected non-secret contract keys;
        # the audit never asks AWS for the rest of the Lambda environment.
        "selected_environment": selected_environment,
    }


def _collect_apis(cli: AwsCli) -> list[dict[str, Any]]:
    apis_result = cli.json("apigatewayv2", "get-apis") or {}
    apis: list[dict[str, Any]] = []
    for item in apis_result.get("Items") or []:
        if not isinstance(item, Mapping) or not item.get("ApiId"):
            continue
        api = dict(item)
        if not isinstance(api.get("Tags"), Mapping):
            resource_arn = f"arn:aws:apigateway:{cli.region}::/apis/{api['ApiId']}"
            tags_result = cli.json(
                "apigatewayv2", "get-tags", "--resource-arn", resource_arn
            ) or {}
            api["Tags"] = tags_result.get("Tags") or {}
        apis.append(api)
    return apis


def _collect_custom_domains(
    cli: AwsCli,
) -> tuple[list[str], list[dict[str, Any]], list[dict[str, Any]]]:
    result = cli.json("apigatewayv2", "get-domain-names") or {}
    items = result.get("Items")
    if not isinstance(items, list):
        raise RuntimeError("API Gateway custom-domain inventory is malformed")

    domain_names: list[str] = []
    domain_configurations: list[dict[str, Any]] = []
    api_mappings: list[dict[str, Any]] = []
    for domain in items:
        if (
            not isinstance(domain, Mapping)
            or not isinstance(domain.get("DomainName"), str)
            or not domain["DomainName"]
        ):
            raise RuntimeError("API Gateway returned a malformed custom domain")
        domain_name = str(domain["DomainName"])
        domain_names.append(domain_name)
        raw_configurations = domain.get("DomainNameConfigurations")
        if not isinstance(raw_configurations, list) or any(
            not isinstance(configuration, Mapping)
            for configuration in raw_configurations
        ):
            raise RuntimeError(
                f"API Gateway returned malformed endpoint configuration for {domain_name}"
            )
        routing_mode = domain.get("RoutingMode")
        if not isinstance(routing_mode, str) or not routing_mode:
            # Older AWS CLI API Gateway models silently omit routing mode.
            # Cloud Control returns resource properties as opaque JSON, so it
            # remains a read-only, fail-closed source with those CLI releases.
            for type_name in (
                "AWS::ApiGateway::DomainName",
                "AWS::ApiGatewayV2::DomainName",
            ):
                resource = cli.json(
                    "cloudcontrol",
                    "get-resource",
                    "--type-name",
                    type_name,
                    "--identifier",
                    domain_name,
                    missing_ok=True,
                )
                if resource is None:
                    continue
                description = resource.get("ResourceDescription")
                encoded_properties = (
                    description.get("Properties")
                    if isinstance(description, Mapping)
                    else None
                )
                if not isinstance(encoded_properties, str):
                    raise RuntimeError(
                        f"Cloud Control returned malformed properties for {domain_name}"
                    )
                try:
                    properties = json.loads(encoded_properties)
                except json.JSONDecodeError as exc:
                    raise RuntimeError(
                        f"Cloud Control returned non-JSON properties for {domain_name}"
                    ) from exc
                if not isinstance(properties, Mapping):
                    raise RuntimeError(
                        f"Cloud Control returned non-object properties for {domain_name}"
                    )
                routing_mode = properties.get("RoutingMode")
                break
        domain_configurations.append(
            {
                "DomainName": domain_name,
                "RoutingMode": routing_mode,
                "DomainNameConfigurations": [
                    {
                        "ApiGatewayDomainName": configuration.get(
                            "ApiGatewayDomainName"
                        ),
                        "CertificateArn": configuration.get("CertificateArn"),
                        "DomainNameStatus": configuration.get("DomainNameStatus"),
                        "EndpointType": configuration.get("EndpointType"),
                        "HostedZoneId": configuration.get("HostedZoneId"),
                        "SecurityPolicy": configuration.get("SecurityPolicy"),
                    }
                    for configuration in raw_configurations
                ],
            }
        )
        mappings = cli.json(
            "apigatewayv2",
            "get-api-mappings",
            "--domain-name",
            domain_name,
        ) or {}
        mapping_items = mappings.get("Items")
        if not isinstance(mapping_items, list) or any(
            not isinstance(mapping, Mapping) for mapping in mapping_items
        ):
            raise RuntimeError(
                f"API Gateway returned malformed mappings for {domain_name}"
            )
        api_mappings.extend(
            {
                "DomainName": domain_name,
                "ApiMappingId": mapping.get("ApiMappingId"),
                "ApiId": mapping.get("ApiId"),
                "Stage": mapping.get("Stage"),
                "ApiMappingKey": mapping.get("ApiMappingKey"),
            }
            for mapping in mapping_items
        )
    return sorted(domain_names), api_mappings, domain_configurations


def collect_cardinality_inventory(cli: AwsCli) -> dict[str, Any]:
    identity = cli.json("sts", "get-caller-identity") or {}
    api_domain_names, api_mappings, api_domain_configurations = (
        _collect_custom_domains(cli)
    )
    return {
        "account_id": identity.get("Account"),
        "caller_arn": identity.get("Arn"),
        "apis": _collect_apis(cli),
        "api_domain_names": api_domain_names,
        "api_mappings": api_mappings,
        "api_domain_configurations": api_domain_configurations,
    }


def _managed_function_summaries(result: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Return every UID Portal Lambda in this account/Region, across old env names."""
    return [
        item
        for item in result.get("Functions") or []
        if isinstance(item, Mapping)
        and str(item.get("FunctionName") or "").startswith(
            UID_PORTAL_FUNCTION_PREFIX
        )
    ]


def collect_inventory(
    cli: AwsCli,
    *,
    api_id: str,
    workers: int,
) -> dict[str, Any]:
    identity = cli.json("sts", "get-caller-identity") or {}
    functions_result = cli.json("lambda", "list-functions") or {}
    apis = _collect_apis(cli)
    candidates = _managed_function_summaries(functions_result)
    api = cli.json("apigatewayv2", "get-api", "--api-id", api_id) or {}
    authorizers = cli.json("apigatewayv2", "get-authorizers", "--api-id", api_id) or {}
    routes = cli.json("apigatewayv2", "get-routes", "--api-id", api_id) or {}
    integrations = cli.json(
        "apigatewayv2", "get-integrations", "--api-id", api_id
    ) or {}
    stages = cli.json("apigatewayv2", "get-stages", "--api-id", api_id) or {}
    api_domain_names, api_mappings, api_domain_configurations = (
        _collect_custom_domains(cli)
    )

    functions: dict[str, Any] = {}
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {pool.submit(_collect_function, cli, item): item for item in candidates}
        for future in as_completed(futures):
            name, data = future.result()
            functions[name] = data

    target_groups_result = cli.json("elbv2", "describe-target-groups") or {}
    lambda_target_groups = []
    for group in target_groups_result.get("TargetGroups") or []:
        if not isinstance(group, Mapping) or group.get("TargetType") != "lambda":
            continue
        arn = str(group.get("TargetGroupArn") or "")
        health = cli.json("elbv2", "describe-target-health", "--target-group-arn", arn) or {}
        targets = [
            description.get("Target", {}).get("Id")
            for description in health.get("TargetHealthDescriptions") or []
            if isinstance(description, Mapping)
        ]
        lambda_target_groups.append(
            {
                "TargetGroupArn": arn,
                "TargetGroupName": group.get("TargetGroupName"),
                "Targets": [target for target in targets if isinstance(target, str)],
            }
        )

    return {
        "account_id": identity.get("Account"),
        "caller_arn": identity.get("Arn"),
        "api_id": api_id,
        "api": api,
        "apis": apis,
        "api_authorizers": authorizers.get("Items") or [],
        "api_routes": routes.get("Items") or [],
        "api_integrations": integrations.get("Items") or [],
        "api_stages": stages.get("Items") or [],
        "api_domain_names": api_domain_names,
        "api_mappings": api_mappings,
        "api_domain_configurations": api_domain_configurations,
        "functions": functions,
        "lambda_target_groups": lambda_target_groups,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--env", required=True, dest="env_name", help="UID environment, e.g. at")
    parser.add_argument("--api-id", help="the surviving API Gateway HTTP API id")
    parser.add_argument(
        "--api-name", help="the one approved API Gateway display name"
    )
    parser.add_argument(
        "--allowed-host",
        help="required exact API custom-domain hostname",
    )
    parser.add_argument(
        "--expected-vpc-config-json",
        help=(
            "canonical non-sensitive lambda_vpc_config Terraform output as JSON; "
            "required outside --cardinality-only mode"
        ),
    )
    parser.add_argument("--region", default="us-west-2")
    parser.add_argument("--profile", help="optional AWS CLI profile")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--workers", type=int, default=8, help="parallel read-only AWS queries")
    parser.add_argument(
        "--cardinality-only",
        action="store_true",
        help=(
            "pre-plan check requiring zero or one exact API/custom-domain "
            "survivor; skips Lambda reads"
        ),
    )
    parser.add_argument("--json", action="store_true", dest="json_output")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not _ENV_NAME.fullmatch(args.env_name):
        print("--env must contain only lower-case letters, digits, and hyphens", file=sys.stderr)
        return 2
    if args.api_id is not None and not _API_ID.fullmatch(args.api_id):
        print("--api-id must be a 10-character lower-case API Gateway id", file=sys.stderr)
        return 2
    if args.api_name is not None and (
        not args.api_name or args.api_name.strip() != args.api_name
    ):
        print("--api-name must be a non-empty API Gateway display name", file=sys.stderr)
        return 2
    if not _REGION.fullmatch(args.region):
        print("--region is not a valid AWS region name", file=sys.stderr)
        return 2
    if args.workers < 1 or args.workers > 32:
        print("--workers must be between 1 and 32", file=sys.stderr)
        return 2

    cli = AwsCli(region=args.region, profile=args.profile)
    if args.cardinality_only:
        if (args.api_id is None) != (args.api_name is None):
            print(
                "--cardinality-only requires --api-id and --api-name together "
                "when Terraform survivor outputs are available",
                file=sys.stderr,
            )
            return 2
        if args.allowed_host is None or not _valid_hostname(args.allowed_host):
            print(
                "--cardinality-only requires --allowed-host as one exact "
                "lower-case DNS hostname",
                file=sys.stderr,
            )
            return 2
        try:
            inventory = collect_cardinality_inventory(cli)
            account_id = str(inventory.get("account_id") or "")
            if not re.fullmatch(r"\d{12}", account_id):
                raise AwsCliError("STS did not return a 12-digit AWS account id")
            findings = audit_api_cardinality(
                inventory,
                expected_api_id=args.api_id,
                expected_api_name=args.api_name,
            )
            cardinality_inventory = {**inventory, "api_id": args.api_id}
            findings.extend(
                _custom_domain_findings(
                    cardinality_inventory,
                    allowed_host=args.allowed_host,
                    allow_absent=True,
                    enforce_account_singleton=args.env_name in {"at", "dev"},
                )
            )
        except (AwsCliError, OSError, RuntimeError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            print(f"LIMITATION: {IDENTITY_POLICY_LIMITATION}", file=sys.stderr)
            return 2

        cardinality_report = {
            "ok": not findings,
            "mode": "cardinality-only",
            "accountId": account_id,
            "managedApiCount": len(_managed_apis(inventory, args.api_name)),
            "customDomainCount": len(inventory.get("api_domain_names") or []),
            "customDomains": inventory.get("api_domain_names") or [],
            "customDomainConfigurations": (
                inventory.get("api_domain_configurations") or []
            ),
            "apiMappings": inventory.get("api_mappings") or [],
            "findings": [asdict(finding) for finding in findings],
            "limitation": IDENTITY_POLICY_LIMITATION,
        }
        if args.json_output:
            print(json.dumps(cardinality_report, indent=2, sort_keys=True))
        elif findings:
            print(f"FAIL: {len(findings)} API cardinality finding(s)")
            for finding in findings:
                print(f"  {finding.code}: {finding.subject}: {finding.detail}")
            print(f"LIMITATION: {IDENTITY_POLICY_LIMITATION}")
        else:
            print(
                "PASS: the target account and Region have no unexpected API "
                "Gateway API or custom domain, and any survivor matches Terraform"
            )
            print(f"LIMITATION: {IDENTITY_POLICY_LIMITATION}")
        return 0 if not findings else 1

    if (
        args.api_id is None
        or args.api_name is None
        or args.allowed_host is None
        or args.expected_vpc_config_json is None
    ):
        print(
            "--api-id, --api-name, --allowed-host, and "
            "--expected-vpc-config-json are required for the full audit",
            file=sys.stderr,
        )
        return 2
    if not _valid_hostname(args.allowed_host):
        print(
            "--allowed-host must be one exact lower-case DNS hostname",
            file=sys.stderr,
        )
        return 2
    try:
        expected_vpc_config = _parse_expected_vpc_config_json(
            args.expected_vpc_config_json
        )
    except ValueError as exc:
        print(f"--expected-vpc-config-json: {exc}", file=sys.stderr)
        return 2

    prefix = f"uid-portal-{args.env_name}-"
    try:
        manifest = _load_manifest(args.manifest)
        inventory = collect_inventory(
            cli, api_id=args.api_id, workers=args.workers
        )
        account_id = str(inventory.get("account_id") or "")
        if not re.fullmatch(r"\d{12}", account_id):
            raise AwsCliError("STS did not return a 12-digit AWS account id")
        matches = [
            item
            for item in inventory.get("api_authorizers") or []
            if isinstance(item, Mapping) and item.get("Name") == "portal_jwt"
        ]
        authorizer_id = str(matches[0]["AuthorizerId"]) if len(matches) == 1 else None
        expected = build_expectations(
            manifest,
            env_name=args.env_name,
            region=args.region,
            account_id=account_id,
            api_id=args.api_id,
            authorizer_id=authorizer_id,
        )
        findings = audit_inventory(
            expected,
            inventory,
            function_prefix=prefix,
            expected_api_name=args.api_name,
            allowed_host=args.allowed_host,
            expected_vpc_config=expected_vpc_config,
            enforce_custom_domain_singleton=args.env_name in {"at", "dev"},
        )
    except (AwsCliError, OSError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        print(f"LIMITATION: {IDENTITY_POLICY_LIMITATION}", file=sys.stderr)
        return 2

    report = {
        "ok": not findings,
        "environment": args.env_name,
        "accountId": account_id,
        "apiId": args.api_id,
        "apiName": args.api_name,
        "environmentFunctionPrefix": prefix,
        "managedFunctionPrefix": UID_PORTAL_FUNCTION_PREFIX,
        "expectedFunctions": len(expected),
        "auditedFunctions": len(inventory.get("functions") or {}),
        "findings": [asdict(finding) for finding in findings],
        "limitation": IDENTITY_POLICY_LIMITATION,
    }
    if args.json_output:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        if findings:
            print(f"FAIL: {len(findings)} Lambda ingress finding(s)")
            for finding in findings:
                print(f"  {finding.code}: {finding.subject}: {finding.detail}")
        else:
            print(
                f"PASS: {report['auditedFunctions']} {UID_PORTAL_FUNCTION_PREFIX} "
                "functions in the target account and Region have only "
                "the expected ingress paths"
            )
        print(f"LIMITATION: {IDENTITY_POLICY_LIMITATION}")
    return 0 if not findings else 1


if __name__ == "__main__":
    sys.exit(main())
