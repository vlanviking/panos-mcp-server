#!/usr/bin/env python3
"""
PAN-OS MCP Server — Model Context Protocol server for managing
Palo Alto Networks firewalls and Panorama appliances.

Exposes read and write tools over the PAN-OS XML API so that an
MCP-compatible client (Claude Desktop, Claude Code, etc.) can
query, configure, and operate PAN-OS devices through natural language.

Environment variables:
    PANOS_HOST      — Firewall or Panorama IP / FQDN  (required)
    PANOS_API_KEY   — API key for authentication       (required)
    PANOS_READONLY  — Set to "true" to disable all write operations
    PANOS_VSYS      — Default vsys (defaults to "vsys1")
    PANOS_LOG_FILE  — Path to audit log (defaults to ./panos_mcp_audit.log)
"""

from __future__ import annotations

import html
import json
import logging
import os
import re
import textwrap
import time
from datetime import datetime, timezone
from typing import Optional
from xml.etree import ElementTree as ET

import pan.xapi
from mcp.server.fastmcp import FastMCP

# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────
PANOS_HOST = os.environ.get("PANOS_HOST", "")
PANOS_API_KEY = os.environ.get("PANOS_API_KEY", "")
PANOS_READONLY = os.environ.get("PANOS_READONLY", "false").lower() == "true"
DEFAULT_VSYS = os.environ.get("PANOS_VSYS", "vsys1")
LOG_FILE = os.environ.get("PANOS_LOG_FILE", "panos_mcp_audit.log")

# ──────────────────────────────────────────────
# Audit logger — every tool invocation is logged
# ──────────────────────────────────────────────
audit_logger = logging.getLogger("panos_mcp_audit")
audit_logger.setLevel(logging.INFO)
_fh = logging.FileHandler(LOG_FILE)
_fh.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
audit_logger.addHandler(_fh)


def audit(tool_name: str, params: dict, result_summary: str = ""):
    """Write a structured audit entry for every tool call."""
    audit_logger.info(
        json.dumps(
            {
                "tool": tool_name,
                "params": params,
                "result_summary": result_summary[:500],
                "host": PANOS_HOST,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
    )


# ──────────────────────────────────────────────
# Input validation helpers
# ──────────────────────────────────────────────
_SAFE_NAME = re.compile(r"^[A-Za-z0-9_\-.:/ ]{1,63}$")
_SAFE_IP = re.compile(
    r"^(any|(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?"
    r"|([0-9a-fA-F:]+(/\d{1,3})?))$"
)


def _validate_name(value: str, field: str = "name") -> str:
    """Reject values that could break XPath / XML injection."""
    value = value.strip()
    if not _SAFE_NAME.match(value):
        raise ValueError(
            f"Invalid {field}: '{value}'. "
            "Only alphanumerics, hyphens, underscores, dots, colons, "
            "slashes, and spaces are allowed (max 63 chars)."
        )
    return value


def _validate_ip(value: str, field: str = "address") -> str:
    value = value.strip()
    if not _SAFE_IP.match(value):
        raise ValueError(f"Invalid {field}: '{value}'. Expected an IP, CIDR, or 'any'.")
    return value


def _validate_action(value: str) -> str:
    allowed = {"allow", "deny", "drop", "reset-client", "reset-server", "reset-both"}
    value = value.strip().lower()
    if value not in allowed:
        raise ValueError(f"Invalid action: '{value}'. Must be one of {allowed}.")
    return value


def _xml_escape(value: str) -> str:
    return html.escape(value, quote=True)


# ──────────────────────────────────────────────
# PAN-OS XML API connection factory
# ──────────────────────────────────────────────
def _get_xapi() -> pan.xapi.PanXapi:
    """Return a fresh PanXapi handle. Raises on missing credentials."""
    if not PANOS_HOST or not PANOS_API_KEY:
        raise RuntimeError(
            "PANOS_HOST and PANOS_API_KEY environment variables must be set."
        )
    return pan.xapi.PanXapi(hostname=PANOS_HOST, api_key=PANOS_API_KEY)


def _xml_to_text(xml_string: str | None) -> str:
    """Best-effort pretty-print of XML, falling back to raw string."""
    if xml_string is None:
        return "(no output)"
    try:
        root = ET.fromstring(f"<root>{xml_string}</root>")
        ET.indent(root)
        parts = []
        for child in root:
            parts.append(ET.tostring(child, encoding="unicode"))
        return "\n".join(parts) if parts else xml_string
    except ET.ParseError:
        return xml_string


def _require_write():
    """Guard that aborts if PANOS_READONLY is set."""
    if PANOS_READONLY:
        raise RuntimeError(
            "This server is running in READ-ONLY mode. "
            "Write operations are disabled. "
            "Unset the PANOS_READONLY env var to enable writes."
        )


# ══════════════════════════════════════════════
# MCP Server definition
# ══════════════════════════════════════════════
mcp = FastMCP("panos-firewall-manager")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  1. SYSTEM & OPERATIONAL TOOLS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@mcp.tool()
def get_system_info() -> str:
    """Retrieve firewall system info: hostname, serial, model, PAN-OS version, uptime, HA state."""
    xapi = _get_xapi()
    xapi.op("<show><system><info></info></system></show>")
    result = _xml_to_text(xapi.xml_result())
    audit("get_system_info", {}, result[:200])
    return result


@mcp.tool()
def get_ha_state() -> str:
    """Show High Availability state and peer info."""
    xapi = _get_xapi()
    xapi.op("<show><high-availability><state></state></high-availability></show>")
    result = _xml_to_text(xapi.xml_result())
    audit("get_ha_state", {}, result[:200])
    return result


@mcp.tool()
def get_jobs(job_id: Optional[str] = None) -> str:
    """Show all jobs or a specific job by ID. Useful for tracking commits and downloads."""
    xapi = _get_xapi()
    if job_id:
        xapi.op(f"<show><jobs><id>{_xml_escape(job_id)}</id></jobs></show>")
    else:
        xapi.op("<show><jobs><all></all></jobs></show>")
    result = _xml_to_text(xapi.xml_result())
    audit("get_jobs", {"job_id": job_id}, result[:200])
    return result


@mcp.tool()
def get_resource_monitor() -> str:
    """Show CPU, memory, disk, and session resource utilization."""
    xapi = _get_xapi()
    xapi.op("<show><running><resource-monitor></resource-monitor></running></show>")
    result = _xml_to_text(xapi.xml_result())
    audit("get_resource_monitor", {}, result[:200])
    return result


@mcp.tool()
def get_session_info() -> str:
    """Show session table summary (counts, usage, limits)."""
    xapi = _get_xapi()
    xapi.op("<show><session><info></info></session></show>")
    result = _xml_to_text(xapi.xml_result())
    audit("get_session_info", {}, result[:200])
    return result


@mcp.tool()
def get_session_id(session_id: str) -> str:
    """Show detail for a single session by its numeric ID."""
    xapi = _get_xapi()
    xapi.op(f"<show><session><id>{_xml_escape(session_id)}</id></session></show>")
    result = _xml_to_text(xapi.xml_result())
    audit("get_session_id", {"session_id": session_id}, result[:200])
    return result


@mcp.tool()
def get_arp_table(interface: Optional[str] = None) -> str:
    """Show ARP table. Optionally filter by interface name."""
    xapi = _get_xapi()
    if interface:
        _validate_name(interface, "interface")
        xapi.op(
            f"<show><arp><entry name='{_xml_escape(interface)}'/></arp></show>"
        )
    else:
        xapi.op("<show><arp><entry name='all'/></arp></show>")
    result = _xml_to_text(xapi.xml_result())
    audit("get_arp_table", {"interface": interface}, result[:200])
    return result


@mcp.tool()
def get_mac_table() -> str:
    """Show the MAC address table (Layer 2 entries)."""
    xapi = _get_xapi()
    xapi.op("<show><mac>all</mac></show>")
    result = _xml_to_text(xapi.xml_result())
    audit("get_mac_table", {}, result[:200])
    return result


@mcp.tool()
def get_counter_global(delta: bool = True) -> str:
    """Show global packet counters. Set delta=False for cumulative."""
    xapi = _get_xapi()
    if delta:
        xapi.op(
            "<show><counter><global><filter>"
            "<delta>yes</delta>"
            "</filter></global></counter></show>"
        )
    else:
        xapi.op("<show><counter><global></global></counter></show>")
    result = _xml_to_text(xapi.xml_result())
    audit("get_counter_global", {"delta": delta}, result[:200])
    return result


@mcp.tool()
def run_op_command(cmd_xml: str) -> str:
    """
    Run an arbitrary PAN-OS operational (show/debug/test) command
    using its XML representation.

    Example cmd_xml: <show><interface>all</interface></show>

    NOTE: This is a power-user escape hatch. Prefer the dedicated
    tools when they cover your use case.
    """
    xapi = _get_xapi()
    xapi.op(cmd_xml)
    result = _xml_to_text(xapi.xml_result())
    audit("run_op_command", {"cmd_xml": cmd_xml}, result[:200])
    return result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  2. NETWORK & INTERFACE TOOLS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@mcp.tool()
def get_interfaces() -> str:
    """Show all interfaces and their status (logical and hardware)."""
    xapi = _get_xapi()
    xapi.op("<show><interface>all</interface></show>")
    result = _xml_to_text(xapi.xml_result())
    audit("get_interfaces", {}, result[:200])
    return result


@mcp.tool()
def get_interface_detail(interface: str) -> str:
    """Show detailed counters and config for a specific interface (e.g. ethernet1/1, ae1, loopback.1)."""
    _validate_name(interface, "interface")
    xapi = _get_xapi()
    xapi.op(f"<show><interface>{_xml_escape(interface)}</interface></show>")
    result = _xml_to_text(xapi.xml_result())
    audit("get_interface_detail", {"interface": interface}, result[:200])
    return result


@mcp.tool()
def get_routing_table(virtual_router: str = "default") -> str:
    """Show the active RIB for a virtual router."""
    _validate_name(virtual_router, "virtual_router")
    xapi = _get_xapi()
    xapi.op(
        f"<show><routing><route><virtual-router>"
        f"{_xml_escape(virtual_router)}"
        f"</virtual-router></route></routing></show>"
    )
    result = _xml_to_text(xapi.xml_result())
    audit("get_routing_table", {"virtual_router": virtual_router}, result[:200])
    return result


@mcp.tool()
def get_routing_summary(virtual_router: str = "default") -> str:
    """Show routing summary (protocol status, route counts) for a virtual router."""
    _validate_name(virtual_router, "virtual_router")
    xapi = _get_xapi()
    xapi.op(
        f"<show><routing><summary><virtual-router>"
        f"{_xml_escape(virtual_router)}"
        f"</virtual-router></summary></routing></show>"
    )
    result = _xml_to_text(xapi.xml_result())
    audit("get_routing_summary", {"virtual_router": virtual_router}, result[:200])
    return result


@mcp.tool()
def get_bgp_peers(virtual_router: str = "default") -> str:
    """Show BGP peer status and statistics."""
    _validate_name(virtual_router, "virtual_router")
    xapi = _get_xapi()
    xapi.op(
        f"<show><routing><protocol><bgp><peer><virtual-router>"
        f"{_xml_escape(virtual_router)}"
        f"</virtual-router></peer></bgp></protocol></routing></show>"
    )
    result = _xml_to_text(xapi.xml_result())
    audit("get_bgp_peers", {"virtual_router": virtual_router}, result[:200])
    return result


@mcp.tool()
def get_bgp_rib(virtual_router: str = "default") -> str:
    """Show the BGP local RIB (all received routes)."""
    _validate_name(virtual_router, "virtual_router")
    xapi = _get_xapi()
    xapi.op(
        f"<show><routing><protocol><bgp><loc-rib><virtual-router>"
        f"{_xml_escape(virtual_router)}"
        f"</virtual-router></loc-rib></bgp></protocol></routing></show>"
    )
    result = _xml_to_text(xapi.xml_result())
    audit("get_bgp_rib", {"virtual_router": virtual_router}, result[:200])
    return result


@mcp.tool()
def get_ospf_neighbors(virtual_router: str = "default") -> str:
    """Show OSPF neighbor adjacencies."""
    _validate_name(virtual_router, "virtual_router")
    xapi = _get_xapi()
    xapi.op(
        f"<show><routing><protocol><ospf><neighbor><virtual-router>"
        f"{_xml_escape(virtual_router)}"
        f"</virtual-router></neighbor></ospf></protocol></routing></show>"
    )
    result = _xml_to_text(xapi.xml_result())
    audit("get_ospf_neighbors", {"virtual_router": virtual_router}, result[:200])
    return result


@mcp.tool()
def get_lldp_neighbors() -> str:
    """Show LLDP neighbor information on all interfaces."""
    xapi = _get_xapi()
    xapi.op("<show><lldp><neighbors>all</neighbors></lldp></show>")
    result = _xml_to_text(xapi.xml_result())
    audit("get_lldp_neighbors", {}, result[:200])
    return result


@mcp.tool()
def get_dhcp_server_leases(interface: Optional[str] = None) -> str:
    """Show DHCP server lease table, optionally filtered by interface."""
    xapi = _get_xapi()
    if interface:
        _validate_name(interface, "interface")
        xapi.op(
            f"<show><dhcp><server><lease><interface>"
            f"{_xml_escape(interface)}"
            f"</interface></lease></server></dhcp></show>"
        )
    else:
        xapi.op("<show><dhcp><server><lease>all</lease></server></dhcp></show>")
    result = _xml_to_text(xapi.xml_result())
    audit("get_dhcp_server_leases", {"interface": interface}, result[:200])
    return result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  3. SECURITY POLICY TOOLS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@mcp.tool()
def get_security_rules(vsys: str = DEFAULT_VSYS) -> str:
    """List all security policy rules in the candidate config for a vsys."""
    _validate_name(vsys, "vsys")
    xapi = _get_xapi()
    xpath = (
        f"/config/devices/entry[@name='localhost.localdomain']"
        f"/vsys/entry[@name='{vsys}']/rulebase/security/rules"
    )
    xapi.get(xpath)
    result = _xml_to_text(xapi.xml_result())
    audit("get_security_rules", {"vsys": vsys}, result[:200])
    return result


@mcp.tool()
def get_security_rule_detail(rule_name: str, vsys: str = DEFAULT_VSYS) -> str:
    """Show a single security rule by name."""
    _validate_name(rule_name, "rule_name")
    _validate_name(vsys, "vsys")
    xapi = _get_xapi()
    xpath = (
        f"/config/devices/entry[@name='localhost.localdomain']"
        f"/vsys/entry[@name='{vsys}']/rulebase/security/rules"
        f"/entry[@name='{_xml_escape(rule_name)}']"
    )
    xapi.get(xpath)
    result = _xml_to_text(xapi.xml_result())
    audit("get_security_rule_detail", {"rule_name": rule_name, "vsys": vsys}, result[:200])
    return result


@mcp.tool()
def add_security_rule(
    name: str,
    source_zone: str,
    dest_zone: str,
    action: str = "allow",
    source_ip: str = "any",
    dest_ip: str = "any",
    application: str = "any",
    service: str = "application-default",
    log_start: bool = False,
    log_end: bool = True,
    log_forwarding_profile: str = "",
    description: str = "",
    tag: str = "",
    disabled: bool = False,
    vsys: str = DEFAULT_VSYS,
) -> str:
    """
    Add a new security policy rule to the CANDIDATE config.
    Does NOT commit — use commit_config to apply.

    Parameters:
        name            — Rule name (unique within the rulebase)
        source_zone     — Source zone (comma-separated for multiple)
        dest_zone       — Destination zone (comma-separated for multiple)
        action          — allow | deny | drop | reset-client | reset-server | reset-both
        source_ip       — Source address/group or 'any' (comma-separated)
        dest_ip         — Destination address/group or 'any' (comma-separated)
        application     — Application name or 'any' (comma-separated)
        service         — Service or 'application-default' (comma-separated)
        log_start       — Log at session start
        log_end         — Log at session end
        log_forwarding_profile — Log forwarding profile name
        description     — Rule description
        tag             — Tag name(s), comma-separated
        disabled        — Create rule in disabled state
        vsys            — Target vsys
    """
    _require_write()
    _validate_name(name, "name")
    _validate_name(vsys, "vsys")
    _validate_action(action)

    def _members(csv: str) -> str:
        return "".join(
            f"<member>{_xml_escape(m.strip())}</member>"
            for m in csv.split(",")
        )

    element_parts = [
        f"<from>{_members(source_zone)}</from>",
        f"<to>{_members(dest_zone)}</to>",
        f"<source>{_members(source_ip)}</source>",
        f"<destination>{_members(dest_ip)}</destination>",
        f"<application>{_members(application)}</application>",
        f"<service>{_members(service)}</service>",
        f"<action>{_xml_escape(action)}</action>",
        f"<log-start>{'yes' if log_start else 'no'}</log-start>",
        f"<log-end>{'yes' if log_end else 'no'}</log-end>",
    ]
    if log_forwarding_profile:
        _validate_name(log_forwarding_profile, "log_forwarding_profile")
        element_parts.append(
            f"<log-setting>{_xml_escape(log_forwarding_profile)}</log-setting>"
        )
    if description:
        element_parts.append(f"<description>{_xml_escape(description)}</description>")
    if tag:
        element_parts.append(f"<tag>{_members(tag)}</tag>")
    if disabled:
        element_parts.append("<disabled>yes</disabled>")

    element = f"<entry name='{_xml_escape(name)}'>{''.join(element_parts)}</entry>"
    xpath = (
        f"/config/devices/entry[@name='localhost.localdomain']"
        f"/vsys/entry[@name='{vsys}']/rulebase/security/rules"
    )
    xapi = _get_xapi()
    xapi.set(xpath, element)
    result = f"Security rule '{name}' added to candidate config. Commit required to activate."
    audit("add_security_rule", {"name": name, "action": action, "vsys": vsys}, result)
    return result


@mcp.tool()
def delete_security_rule(name: str, vsys: str = DEFAULT_VSYS) -> str:
    """Delete a security rule from the CANDIDATE config. Commit required to activate."""
    _require_write()
    _validate_name(name, "name")
    _validate_name(vsys, "vsys")
    xpath = (
        f"/config/devices/entry[@name='localhost.localdomain']"
        f"/vsys/entry[@name='{vsys}']/rulebase/security/rules"
        f"/entry[@name='{_xml_escape(name)}']"
    )
    xapi = _get_xapi()
    xapi.delete(xpath)
    result = f"Security rule '{name}' deleted from candidate config. Commit required."
    audit("delete_security_rule", {"name": name, "vsys": vsys}, result)
    return result


@mcp.tool()
def move_security_rule(
    name: str,
    where: str = "before",
    ref_rule: str = "",
    vsys: str = DEFAULT_VSYS,
) -> str:
    """
    Move a security rule within the rulebase.

    where    — 'top', 'bottom', 'before', or 'after'
    ref_rule — Required when where is 'before' or 'after'
    """
    _require_write()
    _validate_name(name, "name")
    _validate_name(vsys, "vsys")
    if where not in ("top", "bottom", "before", "after"):
        raise ValueError("'where' must be top, bottom, before, or after.")
    if where in ("before", "after") and not ref_rule:
        raise ValueError(f"ref_rule is required when where='{where}'.")
    if ref_rule:
        _validate_name(ref_rule, "ref_rule")

    xpath = (
        f"/config/devices/entry[@name='localhost.localdomain']"
        f"/vsys/entry[@name='{vsys}']/rulebase/security/rules"
        f"/entry[@name='{_xml_escape(name)}']"
    )
    xapi = _get_xapi()
    xapi.move(xpath, where=where, dst=ref_rule if ref_rule else None)
    result = (
        f"Security rule '{name}' moved {where}"
        + (f" '{ref_rule}'" if ref_rule else "")
        + ". Commit required."
    )
    audit("move_security_rule", {"name": name, "where": where, "ref_rule": ref_rule}, result)
    return result


@mcp.tool()
def test_security_policy(
    source_ip: str,
    dest_ip: str,
    dest_port: str,
    protocol: str = "6",
    source_zone: str = "",
    dest_zone: str = "",
    application: str = "",
    vsys: str = DEFAULT_VSYS,
) -> str:
    """
    Test which security rule matches a given traffic flow (policy lookup).

    protocol: 6=TCP, 17=UDP, 1=ICMP
    """
    _validate_ip(source_ip, "source_ip")
    _validate_ip(dest_ip, "dest_ip")
    cmd_parts = [
        "<test><security-policy-match>",
        f"<source>{_xml_escape(source_ip)}</source>",
        f"<destination>{_xml_escape(dest_ip)}</destination>",
        f"<destination-port>{_xml_escape(dest_port)}</destination-port>",
        f"<protocol>{_xml_escape(protocol)}</protocol>",
    ]
    if source_zone:
        cmd_parts.append(f"<from>{_xml_escape(source_zone)}</from>")
    if dest_zone:
        cmd_parts.append(f"<to>{_xml_escape(dest_zone)}</to>")
    if application:
        cmd_parts.append(f"<application>{_xml_escape(application)}</application>")
    cmd_parts.append("</security-policy-match></test>")

    xapi = _get_xapi()
    xapi.op("".join(cmd_parts))
    result = _xml_to_text(xapi.xml_result())
    audit(
        "test_security_policy",
        {"source_ip": source_ip, "dest_ip": dest_ip, "dest_port": dest_port},
        result[:200],
    )
    return result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  4. NAT POLICY TOOLS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@mcp.tool()
def get_nat_rules(vsys: str = DEFAULT_VSYS) -> str:
    """List all NAT rules in the candidate config."""
    _validate_name(vsys, "vsys")
    xapi = _get_xapi()
    xpath = (
        f"/config/devices/entry[@name='localhost.localdomain']"
        f"/vsys/entry[@name='{vsys}']/rulebase/nat/rules"
    )
    xapi.get(xpath)
    result = _xml_to_text(xapi.xml_result())
    audit("get_nat_rules", {"vsys": vsys}, result[:200])
    return result


@mcp.tool()
def add_nat_rule(
    name: str,
    source_zone: str,
    dest_zone: str,
    dest_interface: str = "any",
    source_ip: str = "any",
    dest_ip: str = "any",
    service: str = "any",
    snat_type: str = "",
    snat_address: str = "",
    dnat_address: str = "",
    dnat_port: str = "",
    description: str = "",
    vsys: str = DEFAULT_VSYS,
) -> str:
    """
    Add a NAT rule to the CANDIDATE config. Commit required.

    snat_type — 'dynamic-ip-and-port', 'dynamic-ip', 'static-ip', or '' for no SNAT
    """
    _require_write()
    _validate_name(name, "name")
    _validate_name(vsys, "vsys")

    def _members(csv: str) -> str:
        return "".join(
            f"<member>{_xml_escape(m.strip())}</member>" for m in csv.split(",")
        )

    parts = [
        f"<from>{_members(source_zone)}</from>",
        f"<to>{_members(dest_zone)}</to>",
        f"<source>{_members(source_ip)}</source>",
        f"<destination>{_members(dest_ip)}</destination>",
        f"<service>{_xml_escape(service)}</service>",
        f"<to-interface>{_xml_escape(dest_interface)}</to-interface>",
    ]
    if description:
        parts.append(f"<description>{_xml_escape(description)}</description>")

    # Source NAT
    if snat_type and snat_address:
        if snat_type == "dynamic-ip-and-port":
            parts.append(
                f"<source-translation><dynamic-ip-and-port>"
                f"<translated-address>{_members(snat_address)}</translated-address>"
                f"</dynamic-ip-and-port></source-translation>"
            )
        elif snat_type == "static-ip":
            parts.append(
                f"<source-translation><static-ip>"
                f"<translated-address>{_xml_escape(snat_address)}</translated-address>"
                f"</static-ip></source-translation>"
            )

    # Destination NAT
    if dnat_address:
        dnat_inner = f"<translated-address>{_xml_escape(dnat_address)}</translated-address>"
        if dnat_port:
            dnat_inner += f"<translated-port>{_xml_escape(dnat_port)}</translated-port>"
        parts.append(
            f"<destination-translation>{dnat_inner}</destination-translation>"
        )

    element = f"<entry name='{_xml_escape(name)}'>{''.join(parts)}</entry>"
    xpath = (
        f"/config/devices/entry[@name='localhost.localdomain']"
        f"/vsys/entry[@name='{vsys}']/rulebase/nat/rules"
    )
    xapi = _get_xapi()
    xapi.set(xpath, element)
    result = f"NAT rule '{name}' added to candidate config. Commit required."
    audit("add_nat_rule", {"name": name, "vsys": vsys}, result)
    return result


@mcp.tool()
def delete_nat_rule(name: str, vsys: str = DEFAULT_VSYS) -> str:
    """Delete a NAT rule from the CANDIDATE config."""
    _require_write()
    _validate_name(name, "name")
    _validate_name(vsys, "vsys")
    xpath = (
        f"/config/devices/entry[@name='localhost.localdomain']"
        f"/vsys/entry[@name='{vsys}']/rulebase/nat/rules"
        f"/entry[@name='{_xml_escape(name)}']"
    )
    xapi = _get_xapi()
    xapi.delete(xpath)
    result = f"NAT rule '{name}' deleted from candidate config. Commit required."
    audit("delete_nat_rule", {"name": name, "vsys": vsys}, result)
    return result


@mcp.tool()
def test_nat_policy(
    source_ip: str,
    dest_ip: str,
    dest_port: str,
    protocol: str = "6",
    source_zone: str = "",
    dest_zone: str = "",
) -> str:
    """Test which NAT rule matches a given traffic flow."""
    _validate_ip(source_ip, "source_ip")
    _validate_ip(dest_ip, "dest_ip")
    cmd_parts = [
        "<test><nat-policy-match>",
        f"<source>{_xml_escape(source_ip)}</source>",
        f"<destination>{_xml_escape(dest_ip)}</destination>",
        f"<destination-port>{_xml_escape(dest_port)}</destination-port>",
        f"<protocol>{_xml_escape(protocol)}</protocol>",
    ]
    if source_zone:
        cmd_parts.append(f"<from>{_xml_escape(source_zone)}</from>")
    if dest_zone:
        cmd_parts.append(f"<to>{_xml_escape(dest_zone)}</to>")
    cmd_parts.append("</nat-policy-match></test>")
    xapi = _get_xapi()
    xapi.op("".join(cmd_parts))
    result = _xml_to_text(xapi.xml_result())
    audit("test_nat_policy", {"source_ip": source_ip, "dest_ip": dest_ip}, result[:200])
    return result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  5. OBJECT MANAGEMENT TOOLS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@mcp.tool()
def get_address_objects(vsys: str = DEFAULT_VSYS) -> str:
    """List all address objects in the candidate config."""
    _validate_name(vsys, "vsys")
    xapi = _get_xapi()
    xpath = (
        f"/config/devices/entry[@name='localhost.localdomain']"
        f"/vsys/entry[@name='{vsys}']/address"
    )
    xapi.get(xpath)
    result = _xml_to_text(xapi.xml_result())
    audit("get_address_objects", {"vsys": vsys}, result[:200])
    return result


@mcp.tool()
def add_address_object(
    name: str,
    value: str,
    addr_type: str = "ip-netmask",
    description: str = "",
    tag: str = "",
    vsys: str = DEFAULT_VSYS,
) -> str:
    """
    Create an address object.

    addr_type — 'ip-netmask', 'ip-range', 'fqdn'
    value     — e.g. '10.0.0.0/24', '10.0.0.1-10.0.0.50', 'www.example.com'
    """
    _require_write()
    _validate_name(name, "name")
    _validate_name(vsys, "vsys")
    if addr_type not in ("ip-netmask", "ip-range", "fqdn"):
        raise ValueError("addr_type must be 'ip-netmask', 'ip-range', or 'fqdn'.")

    parts = [f"<{addr_type}>{_xml_escape(value)}</{addr_type}>"]
    if description:
        parts.append(f"<description>{_xml_escape(description)}</description>")
    if tag:
        members = "".join(
            f"<member>{_xml_escape(t.strip())}</member>" for t in tag.split(",")
        )
        parts.append(f"<tag>{members}</tag>")

    element = f"<entry name='{_xml_escape(name)}'>{''.join(parts)}</entry>"
    xpath = (
        f"/config/devices/entry[@name='localhost.localdomain']"
        f"/vsys/entry[@name='{vsys}']/address"
    )
    xapi = _get_xapi()
    xapi.set(xpath, element)
    result = f"Address object '{name}' created. Commit required."
    audit("add_address_object", {"name": name, "type": addr_type, "value": value}, result)
    return result


@mcp.tool()
def delete_address_object(name: str, vsys: str = DEFAULT_VSYS) -> str:
    """Delete an address object from the candidate config."""
    _require_write()
    _validate_name(name, "name")
    _validate_name(vsys, "vsys")
    xpath = (
        f"/config/devices/entry[@name='localhost.localdomain']"
        f"/vsys/entry[@name='{vsys}']/address"
        f"/entry[@name='{_xml_escape(name)}']"
    )
    xapi = _get_xapi()
    xapi.delete(xpath)
    result = f"Address object '{name}' deleted. Commit required."
    audit("delete_address_object", {"name": name, "vsys": vsys}, result)
    return result


@mcp.tool()
def get_address_groups(vsys: str = DEFAULT_VSYS) -> str:
    """List all address groups."""
    _validate_name(vsys, "vsys")
    xapi = _get_xapi()
    xpath = (
        f"/config/devices/entry[@name='localhost.localdomain']"
        f"/vsys/entry[@name='{vsys}']/address-group"
    )
    xapi.get(xpath)
    result = _xml_to_text(xapi.xml_result())
    audit("get_address_groups", {"vsys": vsys}, result[:200])
    return result


@mcp.tool()
def add_address_group(
    name: str,
    members: str,
    group_type: str = "static",
    match_filter: str = "",
    description: str = "",
    vsys: str = DEFAULT_VSYS,
) -> str:
    """
    Create an address group.

    group_type — 'static' or 'dynamic'
    members    — Comma-separated address object names (static) or ignored for dynamic
    match_filter — Tag-based filter for dynamic groups, e.g. "'web-servers'"
    """
    _require_write()
    _validate_name(name, "name")
    _validate_name(vsys, "vsys")

    parts = []
    if group_type == "static":
        member_xml = "".join(
            f"<member>{_xml_escape(m.strip())}</member>" for m in members.split(",")
        )
        parts.append(f"<static>{member_xml}</static>")
    elif group_type == "dynamic":
        if not match_filter:
            raise ValueError("match_filter is required for dynamic address groups.")
        parts.append(f"<dynamic><filter>{_xml_escape(match_filter)}</filter></dynamic>")
    else:
        raise ValueError("group_type must be 'static' or 'dynamic'.")
    if description:
        parts.append(f"<description>{_xml_escape(description)}</description>")

    element = f"<entry name='{_xml_escape(name)}'>{''.join(parts)}</entry>"
    xpath = (
        f"/config/devices/entry[@name='localhost.localdomain']"
        f"/vsys/entry[@name='{vsys}']/address-group"
    )
    xapi = _get_xapi()
    xapi.set(xpath, element)
    result = f"Address group '{name}' created. Commit required."
    audit("add_address_group", {"name": name, "group_type": group_type}, result)
    return result


@mcp.tool()
def get_service_objects(vsys: str = DEFAULT_VSYS) -> str:
    """List all service objects."""
    _validate_name(vsys, "vsys")
    xapi = _get_xapi()
    xpath = (
        f"/config/devices/entry[@name='localhost.localdomain']"
        f"/vsys/entry[@name='{vsys}']/service"
    )
    xapi.get(xpath)
    result = _xml_to_text(xapi.xml_result())
    audit("get_service_objects", {"vsys": vsys}, result[:200])
    return result


@mcp.tool()
def add_service_object(
    name: str,
    protocol: str,
    dest_port: str,
    source_port: str = "",
    description: str = "",
    vsys: str = DEFAULT_VSYS,
) -> str:
    """
    Create a service object.

    protocol  — 'tcp' or 'udp'
    dest_port — Port or range, e.g. '443' or '8000-8080'
    """
    _require_write()
    _validate_name(name, "name")
    _validate_name(vsys, "vsys")
    protocol = protocol.strip().lower()
    if protocol not in ("tcp", "udp"):
        raise ValueError("protocol must be 'tcp' or 'udp'.")

    proto_parts = [f"<port>{_xml_escape(dest_port)}</port>"]
    if source_port:
        proto_parts.append(f"<source-port>{_xml_escape(source_port)}</source-port>")
    parts = [f"<protocol><{protocol}>{''.join(proto_parts)}</{protocol}></protocol>"]
    if description:
        parts.append(f"<description>{_xml_escape(description)}</description>")

    element = f"<entry name='{_xml_escape(name)}'>{''.join(parts)}</entry>"
    xpath = (
        f"/config/devices/entry[@name='localhost.localdomain']"
        f"/vsys/entry[@name='{vsys}']/service"
    )
    xapi = _get_xapi()
    xapi.set(xpath, element)
    result = f"Service object '{name}' created. Commit required."
    audit("add_service_object", {"name": name, "protocol": protocol, "dest_port": dest_port}, result)
    return result


@mcp.tool()
def get_tags(vsys: str = DEFAULT_VSYS) -> str:
    """List all tag objects."""
    _validate_name(vsys, "vsys")
    xapi = _get_xapi()
    xpath = (
        f"/config/devices/entry[@name='localhost.localdomain']"
        f"/vsys/entry[@name='{vsys}']/tag"
    )
    xapi.get(xpath)
    result = _xml_to_text(xapi.xml_result())
    audit("get_tags", {"vsys": vsys}, result[:200])
    return result


@mcp.tool()
def get_application_filter_info(application: str) -> str:
    """Show details for a PAN-OS application (built-in App-ID)."""
    _validate_name(application, "application")
    xapi = _get_xapi()
    xapi.op(
        f"<show><application><info><name>{_xml_escape(application)}</name></info></application></show>"
    )
    result = _xml_to_text(xapi.xml_result())
    audit("get_application_filter_info", {"application": application}, result[:200])
    return result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  6. VPN / IPSEC TOOLS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@mcp.tool()
def get_ipsec_tunnels() -> str:
    """Show all IPsec tunnel status and stats."""
    xapi = _get_xapi()
    xapi.op("<show><vpn><ipsec-sa></ipsec-sa></vpn></show>")
    result = _xml_to_text(xapi.xml_result())
    audit("get_ipsec_tunnels", {}, result[:200])
    return result


@mcp.tool()
def get_ike_gateways() -> str:
    """Show IKE gateway (Phase 1) status."""
    xapi = _get_xapi()
    xapi.op("<show><vpn><ike-sa></ike-sa></vpn></show>")
    result = _xml_to_text(xapi.xml_result())
    audit("get_ike_gateways", {}, result[:200])
    return result


@mcp.tool()
def get_gre_tunnels() -> str:
    """Show GRE tunnel status."""
    xapi = _get_xapi()
    xapi.op("<show><vpn><flow></flow></vpn></show>")
    result = _xml_to_text(xapi.xml_result())
    audit("get_gre_tunnels", {}, result[:200])
    return result


@mcp.tool()
def get_globalprotect_gateways() -> str:
    """Show GlobalProtect gateway status and connected users."""
    xapi = _get_xapi()
    xapi.op(
        "<show><global-protect-gateway><current-user></current-user></global-protect-gateway></show>"
    )
    result = _xml_to_text(xapi.xml_result())
    audit("get_globalprotect_gateways", {}, result[:200])
    return result


@mcp.tool()
def disconnect_globalprotect_user(user: str, gateway: str, computer: str = "") -> str:
    """Disconnect a GlobalProtect user from a gateway."""
    _require_write()
    _validate_name(user, "user")
    _validate_name(gateway, "gateway")
    cmd = (
        f"<request><global-protect-gateway><client-logout>"
        f"<gateway>{_xml_escape(gateway)}</gateway>"
        f"<user>{_xml_escape(user)}</user>"
    )
    if computer:
        cmd += f"<computer>{_xml_escape(computer)}</computer>"
    cmd += "</client-logout></global-protect-gateway></request>"
    xapi = _get_xapi()
    xapi.op(cmd)
    result = _xml_to_text(xapi.xml_result())
    audit("disconnect_globalprotect_user", {"user": user, "gateway": gateway}, result[:200])
    return result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  7. USER-ID TOOLS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@mcp.tool()
def get_userid_ip_user_mapping() -> str:
    """Show all User-ID IP-to-user mappings on the firewall."""
    xapi = _get_xapi()
    xapi.op("<show><user><ip-user-mapping><all></all></ip-user-mapping></user></show>")
    result = _xml_to_text(xapi.xml_result())
    audit("get_userid_ip_user_mapping", {}, result[:200])
    return result


@mcp.tool()
def register_userid_mapping(ip: str, user: str, timeout: int = 60) -> str:
    """Register a User-ID IP-to-user mapping via the XML API."""
    _require_write()
    _validate_ip(ip, "ip")
    uid_msg = (
        f"<uid-message><type>update</type><payload><login>"
        f"<entry name='{_xml_escape(user)}' ip='{_xml_escape(ip)}' "
        f"timeout='{timeout}'/>"
        f"</login></payload></uid-message>"
    )
    xapi = _get_xapi()
    xapi.user_id(cmd=uid_msg)
    result = f"Registered mapping {ip} -> {user} (timeout={timeout}m)."
    audit("register_userid_mapping", {"ip": ip, "user": user}, result)
    return result


@mcp.tool()
def unregister_userid_mapping(ip: str, user: str) -> str:
    """Remove a User-ID IP-to-user mapping."""
    _require_write()
    _validate_ip(ip, "ip")
    uid_msg = (
        f"<uid-message><type>update</type><payload><logout>"
        f"<entry name='{_xml_escape(user)}' ip='{_xml_escape(ip)}'/>"
        f"</logout></payload></uid-message>"
    )
    xapi = _get_xapi()
    xapi.user_id(cmd=uid_msg)
    result = f"Removed mapping {ip} -> {user}."
    audit("unregister_userid_mapping", {"ip": ip, "user": user}, result)
    return result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  8. LOG & THREAT TOOLS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@mcp.tool()
def get_traffic_logs(query: str = "", num_logs: int = 20) -> str:
    """
    Retrieve traffic logs. Optionally filter with a PAN-OS log query.

    Example query: "( addr.src in 10.0.0.0/8 ) and ( app eq ssl )"
    """
    xapi = _get_xapi()
    xapi.log(
        log_type="traffic",
        nlogs=str(num_logs),
        filter=query if query else None,
    )
    result = _xml_to_text(xapi.xml_result())
    audit("get_traffic_logs", {"query": query, "num_logs": num_logs}, result[:200])
    return result


@mcp.tool()
def get_threat_logs(query: str = "", num_logs: int = 20) -> str:
    """Retrieve threat logs with optional PAN-OS log filter."""
    xapi = _get_xapi()
    xapi.log(
        log_type="threat",
        nlogs=str(num_logs),
        filter=query if query else None,
    )
    result = _xml_to_text(xapi.xml_result())
    audit("get_threat_logs", {"query": query, "num_logs": num_logs}, result[:200])
    return result


@mcp.tool()
def get_system_logs(query: str = "", num_logs: int = 20) -> str:
    """Retrieve system logs with optional filter."""
    xapi = _get_xapi()
    xapi.log(
        log_type="system",
        nlogs=str(num_logs),
        filter=query if query else None,
    )
    result = _xml_to_text(xapi.xml_result())
    audit("get_system_logs", {"query": query, "num_logs": num_logs}, result[:200])
    return result


@mcp.tool()
def get_config_logs(query: str = "", num_logs: int = 20) -> str:
    """Retrieve configuration audit logs."""
    xapi = _get_xapi()
    xapi.log(
        log_type="config",
        nlogs=str(num_logs),
        filter=query if query else None,
    )
    result = _xml_to_text(xapi.xml_result())
    audit("get_config_logs", {"query": query, "num_logs": num_logs}, result[:200])
    return result


@mcp.tool()
def get_url_logs(query: str = "", num_logs: int = 20) -> str:
    """Retrieve URL filtering logs."""
    xapi = _get_xapi()
    xapi.log(
        log_type="url",
        nlogs=str(num_logs),
        filter=query if query else None,
    )
    result = _xml_to_text(xapi.xml_result())
    audit("get_url_logs", {"query": query, "num_logs": num_logs}, result[:200])
    return result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  9. COMMIT & CONFIG MANAGEMENT TOOLS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@mcp.tool()
def show_config_diff() -> str:
    """Show the diff between the candidate config and the running config."""
    xapi = _get_xapi()
    xapi.op("<show><config><diff></diff></config></show>")
    result = _xml_to_text(xapi.xml_result())
    audit("show_config_diff", {}, result[:200])
    return result


@mcp.tool()
def validate_config() -> str:
    """Validate the candidate config without committing."""
    xapi = _get_xapi()
    xapi.op("<validate><full></full></validate>")
    result = _xml_to_text(xapi.xml_result())
    audit("validate_config", {}, result[:200])
    return result


@mcp.tool()
def commit_config(
    description: str = "",
    force: bool = False,
    partial_admin: str = "",
) -> str:
    """
    Commit the candidate config to running.

    description   — Commit description for the audit log
    force         — Force commit even if other admins have locks
    partial_admin — Commit only changes made by this admin (partial commit)
    """
    _require_write()

    parts = ["<commit>"]
    if description:
        parts.append(f"<description>{_xml_escape(description)}</description>")
    if force:
        parts.append("<force></force>")
    if partial_admin:
        parts.append(
            f"<partial><admin><member>{_xml_escape(partial_admin)}</member>"
            f"</admin></partial>"
        )
    parts.append("</commit>")

    xapi = _get_xapi()
    xapi.commit(cmd="".join(parts))
    result = _xml_to_text(xapi.xml_result())
    audit(
        "commit_config",
        {"description": description, "force": force, "partial_admin": partial_admin},
        result[:200],
    )
    return f"Commit initiated. {result}"


@mcp.tool()
def revert_config() -> str:
    """Revert the candidate config to the running config (discard all pending changes)."""
    _require_write()
    xapi = _get_xapi()
    xapi.op("<load><config><from>running-config.xml</from></config></load>")
    result = _xml_to_text(xapi.xml_result())
    audit("revert_config", {}, result[:200])
    return f"Candidate config reverted to running config. {result}"


@mcp.tool()
def save_named_snapshot(name: str) -> str:
    """Save the running config to a named snapshot file on the firewall."""
    _require_write()
    _validate_name(name, "snapshot_name")
    xapi = _get_xapi()
    xapi.op(f"<save><config><to>{_xml_escape(name)}</to></config></save>")
    result = _xml_to_text(xapi.xml_result())
    audit("save_named_snapshot", {"name": name}, result[:200])
    return f"Config saved as '{name}'. {result}"


@mcp.tool()
def load_named_snapshot(name: str) -> str:
    """Load a named config snapshot into the candidate config. Commit required to activate."""
    _require_write()
    _validate_name(name, "snapshot_name")
    xapi = _get_xapi()
    xapi.op(f"<load><config><from>{_xml_escape(name)}</from></config></load>")
    result = _xml_to_text(xapi.xml_result())
    audit("load_named_snapshot", {"name": name}, result[:200])
    return f"Snapshot '{name}' loaded into candidate config. Commit required. {result}"


@mcp.tool()
def get_config_backups() -> str:
    """List available config backup/snapshot files on the firewall."""
    xapi = _get_xapi()
    xapi.op("<show><config><saved></saved></config></show>")
    result = _xml_to_text(xapi.xml_result())
    audit("get_config_backups", {}, result[:200])
    return result


@mcp.tool()
def export_running_config() -> str:
    """Export the full running config as XML text."""
    xapi = _get_xapi()
    xapi.show("/config")
    result = _xml_to_text(xapi.xml_result())
    audit("export_running_config", {}, f"exported {len(result)} chars")
    return result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  10. PANORAMA-SPECIFIC TOOLS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@mcp.tool()
def get_managed_devices() -> str:
    """(Panorama only) List all managed firewalls and their connection status."""
    xapi = _get_xapi()
    xapi.op("<show><devices><all></all></devices></show>")
    result = _xml_to_text(xapi.xml_result())
    audit("get_managed_devices", {}, result[:200])
    return result


@mcp.tool()
def get_device_groups() -> str:
    """(Panorama only) List all device groups."""
    xapi = _get_xapi()
    xpath = "/config/devices/entry[@name='localhost.localdomain']/device-group"
    xapi.get(xpath)
    result = _xml_to_text(xapi.xml_result())
    audit("get_device_groups", {}, result[:200])
    return result


@mcp.tool()
def get_template_stacks() -> str:
    """(Panorama only) List all template stacks."""
    xapi = _get_xapi()
    xpath = "/config/devices/entry[@name='localhost.localdomain']/template-stack"
    xapi.get(xpath)
    result = _xml_to_text(xapi.xml_result())
    audit("get_template_stacks", {}, result[:200])
    return result


@mcp.tool()
def push_to_devices(
    device_group: str = "",
    template_stack: str = "",
    serial_numbers: str = "",
    description: str = "",
) -> str:
    """
    (Panorama only) Push configuration to managed firewalls.

    Provide device_group for policy/object pushes,
    template_stack for network/device config pushes,
    or serial_numbers (comma-separated) for targeted pushes.
    """
    _require_write()

    if device_group:
        _validate_name(device_group, "device_group")
        cmd = (
            f"<commit-all><shared-policy><device-group>"
            f"<entry name='{_xml_escape(device_group)}'/>"
            f"</device-group>"
        )
        if description:
            cmd += f"<description>{_xml_escape(description)}</description>"
        cmd += "</shared-policy></commit-all>"
    elif template_stack:
        _validate_name(template_stack, "template_stack")
        cmd = (
            f"<commit-all><template-stack>"
            f"<name>{_xml_escape(template_stack)}</name>"
        )
        if description:
            cmd += f"<description>{_xml_escape(description)}</description>"
        cmd += "</template-stack></commit-all>"
    elif serial_numbers:
        members = "".join(
            f"<member>{_xml_escape(s.strip())}</member>"
            for s in serial_numbers.split(",")
        )
        cmd = (
            f"<commit-all><shared-policy><device-group>"
            f"<entry name='shared'/></device-group>"
            f"<filter><devices>{members}</devices></filter>"
            f"</shared-policy></commit-all>"
        )
    else:
        return "Error: Provide device_group, template_stack, or serial_numbers."

    xapi = _get_xapi()
    xapi.commit(action="all", cmd=cmd)
    result = _xml_to_text(xapi.xml_result())
    audit(
        "push_to_devices",
        {
            "device_group": device_group,
            "template_stack": template_stack,
            "serial_numbers": serial_numbers,
        },
        result[:200],
    )
    return f"Push initiated. {result}"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  11. HA OPERATIONS TOOLS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@mcp.tool()
def ha_suspend() -> str:
    """Suspend HA on the local device (make it passive)."""
    _require_write()
    xapi = _get_xapi()
    xapi.op(
        "<request><high-availability><state><suspend></suspend></state>"
        "</high-availability></request>"
    )
    result = _xml_to_text(xapi.xml_result())
    audit("ha_suspend", {}, result[:200])
    return result


@mcp.tool()
def ha_functional() -> str:
    """Return the local HA device to functional (active-eligible) state."""
    _require_write()
    xapi = _get_xapi()
    xapi.op(
        "<request><high-availability><state><functional></functional></state>"
        "</high-availability></request>"
    )
    result = _xml_to_text(xapi.xml_result())
    audit("ha_functional", {}, result[:200])
    return result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  12. CONTENT UPDATE & SOFTWARE TOOLS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@mcp.tool()
def check_content_updates() -> str:
    """Check for available content (App-ID / Threat) updates."""
    xapi = _get_xapi()
    xapi.op("<request><content><upgrade><check></check></upgrade></content></request>")
    result = _xml_to_text(xapi.xml_result())
    audit("check_content_updates", {}, result[:200])
    return result


@mcp.tool()
def check_software_updates() -> str:
    """Check for available PAN-OS software updates."""
    xapi = _get_xapi()
    xapi.op("<request><system><software><check></check></software></system></request>")
    result = _xml_to_text(xapi.xml_result())
    audit("check_software_updates", {}, result[:200])
    return result


@mcp.tool()
def download_content_update(version: str = "latest") -> str:
    """Download a content update. Use 'latest' for the most recent."""
    _require_write()
    xapi = _get_xapi()
    xapi.op(
        f"<request><content><upgrade><download>"
        f"<latest></latest>"
        f"</download></upgrade></content></request>"
    )
    result = _xml_to_text(xapi.xml_result())
    audit("download_content_update", {"version": version}, result[:200])
    return f"Content download initiated. Track with get_jobs(). {result}"


@mcp.tool()
def install_content_update(version: str = "latest") -> str:
    """Install a previously downloaded content update."""
    _require_write()
    xapi = _get_xapi()
    xapi.op(
        f"<request><content><upgrade><install>"
        f"<version>{_xml_escape(version)}</version>"
        f"</install></upgrade></content></request>"
    )
    result = _xml_to_text(xapi.xml_result())
    audit("install_content_update", {"version": version}, result[:200])
    return f"Content install initiated. {result}"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  13. XPATH POWER TOOLS (Advanced)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@mcp.tool()
def xpath_get(xpath: str) -> str:
    """
    Read any config node by XPath (candidate config).

    Example: /config/devices/entry/vsys/entry[@name='vsys1']/zone
    """
    xapi = _get_xapi()
    xapi.get(xpath)
    result = _xml_to_text(xapi.xml_result())
    audit("xpath_get", {"xpath": xpath}, result[:200])
    return result


@mcp.tool()
def xpath_set(xpath: str, element: str) -> str:
    """
    Set (merge) an XML element at the given XPath in the candidate config.

    This is a power-user tool. Prefer the dedicated tools when possible.
    Commit required after changes.
    """
    _require_write()
    xapi = _get_xapi()
    xapi.set(xpath, element)
    result = f"Element set at {xpath}. Commit required."
    audit("xpath_set", {"xpath": xpath, "element": element[:200]}, result)
    return result


@mcp.tool()
def xpath_delete(xpath: str) -> str:
    """
    Delete a config node by XPath from the candidate config.
    Commit required after changes.
    """
    _require_write()
    xapi = _get_xapi()
    xapi.delete(xpath)
    result = f"Deleted node at {xpath}. Commit required."
    audit("xpath_delete", {"xpath": xpath}, result)
    return result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  MCP RESOURCES — read-only data for context
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@mcp.resource("panos://config/running")
def resource_running_config() -> str:
    """Full running configuration XML."""
    xapi = _get_xapi()
    xapi.show("/config")
    return _xml_to_text(xapi.xml_result())


@mcp.resource("panos://config/candidate")
def resource_candidate_config() -> str:
    """Full candidate configuration XML."""
    xapi = _get_xapi()
    xapi.get("/config")
    return _xml_to_text(xapi.xml_result())


@mcp.resource("panos://system/info")
def resource_system_info() -> str:
    """System information snapshot."""
    xapi = _get_xapi()
    xapi.op("<show><system><info></info></system></show>")
    return _xml_to_text(xapi.xml_result())


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  MCP PROMPTS — reusable prompt templates
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@mcp.prompt()
def security_audit() -> str:
    """Prompt to perform a security rule audit."""
    return textwrap.dedent("""\
        Please perform a security audit of this PAN-OS firewall:

        1. Pull all security rules and identify:
           - Rules with action 'allow' and application 'any'
           - Rules with source or destination of 'any'
           - Disabled rules that might be stale
           - Rules with no logging enabled
        2. Check for overlapping or shadowed rules
        3. Review the threat and URL filtering logs for recent blocks
        4. Summarize findings with risk ratings (High/Medium/Low)
    """)


@mcp.prompt()
def change_window_checklist() -> str:
    """Prompt for a structured change-window workflow."""
    return textwrap.dedent("""\
        I'm entering a change window. Please help me with this workflow:

        1. Take a pre-change config snapshot (save_named_snapshot)
        2. Show the current config diff (should be clean)
        3. I'll describe the changes — please make them
        4. Validate the candidate config
        5. Show the diff for my review
        6. Wait for my explicit "commit" approval
        7. After commit, verify the change took effect
        8. If anything goes wrong, revert to the snapshot
    """)


@mcp.prompt()
def troubleshoot_connectivity(
    source_ip: str, dest_ip: str, dest_port: str
) -> str:
    """Prompt to troubleshoot a connectivity issue."""
    return textwrap.dedent(f"""\
        A user reports they can't reach {dest_ip}:{dest_port} from {source_ip}.
        Please troubleshoot systematically:

        1. Test security policy match for this flow
        2. Test NAT policy match
        3. Check the routing table for the destination
        4. Look for recent deny/drop entries in traffic logs
        5. Check threat logs for any blocks
        6. Verify the relevant interfaces are up
        7. Summarize findings and suggest a fix
    """)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Entry point
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

if __name__ == "__main__":
    print(f"Starting PAN-OS MCP Server targeting {PANOS_HOST or '(not configured)'}")
    print(f"Read-only mode: {PANOS_READONLY}")
    print(f"Default vsys: {DEFAULT_VSYS}")
    print(f"Audit log: {LOG_FILE}")
    mcp.run(transport="stdio")