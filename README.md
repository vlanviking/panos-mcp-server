# PAN-OS MCP Server

A Model Context Protocol (MCP) server for managing Palo Alto Networks firewalls and Panorama appliances through natural language via Claude Desktop, Claude Code, or any MCP-compatible client.

## Features

**65+ tools** organized across 13 functional areas:

| Category | Tools | Examples |
|---|---|---|
| System & Ops | 11 | System info, HA state, sessions, ARP, counters, resource monitor |
| Network & Interfaces | 9 | Interfaces, routing table, BGP peers/RIB, OSPF neighbors, LLDP, DHCP |
| Security Policy | 6 | List/add/delete/move rules, policy match test |
| NAT Policy | 4 | List/add/delete rules, NAT match test |
| Object Management | 8 | Address objects/groups, services, tags, App-ID lookup |
| VPN / IPsec | 5 | IPsec SAs, IKE gateways, GRE, GlobalProtect users |
| User-ID | 3 | IP-user mappings, register/unregister |
| Logs & Threats | 5 | Traffic, threat, system, config, URL logs with filters |
| Commit & Config | 8 | Diff, validate, commit, revert, snapshots, export |
| Panorama | 4 | Managed devices, device groups, template stacks, push |
| HA Operations | 2 | Suspend, return to functional |
| Content Updates | 4 | Check/download/install content & software updates |
| XPath Power Tools | 3 | Raw XPath get/set/delete for advanced use |

Plus **3 MCP Resources** (running config, candidate config, system info) and **3 MCP Prompts** (security audit, change window checklist, connectivity troubleshooting).

## Prerequisites

- Python 3.10+
- Network access to your PAN-OS device's management interface
- A PAN-OS API key ([how to generate one](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-panorama-api/get-started-with-the-pan-os-xml-api/get-your-api-key))

## Installation

```bash
cd panos-mcp-server
pip install -r requirements.txt
```

## Configuration

The server is configured entirely through environment variables:

| Variable | Required | Default | Description |
|---|---|---|---|
| `PANOS_HOST` | Yes | — | Firewall or Panorama IP/FQDN |
| `PANOS_API_KEY` | Yes | — | API key for authentication |
| `PANOS_READONLY` | No | `false` | Set `true` to disable all write operations |
| `PANOS_VSYS` | No | `vsys1` | Default vsys for policy/object tools |
| `PANOS_LOG_FILE` | No | `./panos_mcp_audit.log` | Path to the audit log file |

### Generate an API Key

```bash
curl -k -X POST "https://<firewall>/api/?type=keygen&user=admin&password=yourpassword"
```

## Usage

### Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "panos": {
      "command": "python",
      "args": ["/absolute/path/to/panos-mcp-server/server.py"],
      "env": {
        "PANOS_HOST": "192.168.1.1",
        "PANOS_API_KEY": "LUFRPT1...",
        "PANOS_READONLY": "false",
        "PANOS_VSYS": "vsys1"
      }
    }
  }
}
```

### Claude Code

Add to `.claude/settings.json` in your project or home directory:

```json
{
  "mcpServers": {
    "panos": {
      "command": "python",
      "args": ["./panos-mcp-server/server.py"],
      "env": {
        "PANOS_HOST": "10.0.0.1",
        "PANOS_API_KEY": "LUFRPT1..."
      }
    }
  }
}
```

### Standalone (for testing)

```bash
export PANOS_HOST="192.168.1.1"
export PANOS_API_KEY="LUFRPT1..."
python server.py
```

## Safety Features

### Read-Only Mode

Set `PANOS_READONLY=true` to completely disable all write operations (add, delete, commit, push, HA changes). Ideal for monitoring dashboards or giving read access to junior staff.

### No Auto-Commit

Write tools only modify the **candidate config**. A separate, explicit `commit_config` call is always required. This gives you a review step before any change goes live.

### Input Validation

All user-supplied values (names, IPs, actions) are validated against strict regexes before being inserted into XPath expressions or XML elements, preventing injection attacks.

### Audit Logging

Every tool invocation is logged to `panos_mcp_audit.log` with:
- Timestamp (UTC)
- Tool name
- Parameters
- Result summary
- Target host

### Least-Privilege API Keys

Use PAN-OS admin roles to scope the API key:
- **Monitoring role** — for read-only deployments
- **Device admin** — for full config management
- **Superuser** — only if Panorama push operations are needed

## Example Conversations

**Check firewall health:**
> "What's the system info and HA status on the firewall?"

**Troubleshoot connectivity:**
> "A user at 10.1.50.100 can't reach 172.16.0.5 on port 443. Can you troubleshoot?"

**Add a rule:**
> "Add a security rule called 'Allow-Guest-HTTPS' from zone Guest to zone Internet, application ssl, action allow, with logging enabled."

**Review before committing:**
> "Show me the config diff, then validate it."

**Change window:**
> "Take a snapshot called 'pre-change-apr02', then let's make some changes."

**BGP status:**
> "Show me the BGP peers and the local RIB on the default virtual router."

**Panorama push:**
> "Push the shared policy to the 'Prod-IT' device group."

## Multi-Firewall Setup

To manage multiple firewalls, register multiple MCP server instances with different env vars:

```json
{
  "mcpServers": {
    "panos-clv": {
      "command": "python",
      "args": ["/path/to/server.py"],
      "env": { "PANOS_HOST": "10.1.0.1", "PANOS_API_KEY": "KEY1..." }
    },
    "panos-dlv": {
      "command": "python",
      "args": ["/path/to/server.py"],
      "env": { "PANOS_HOST": "10.2.0.1", "PANOS_API_KEY": "KEY2..." }
    },
    "panorama": {
      "command": "python",
      "args": ["/path/to/server.py"],
      "env": { "PANOS_HOST": "10.0.0.10", "PANOS_API_KEY": "KEY3..." }
    }
  }
}
```

## Extending the Server

Adding a new tool is straightforward:

```python
@mcp.tool()
def my_new_tool(param1: str, param2: int = 10) -> str:
    """Docstring becomes the tool description shown to Claude."""
    _require_write()  # Include this line if the tool modifies config
    _validate_name(param1, "param1")  # Validate inputs
    
    xapi = _get_xapi()
    xapi.op("<your><xml><command/></xml></your>")
    result = _xml_to_text(xapi.xml_result())
    
    audit("my_new_tool", {"param1": param1}, result[:200])
    return result
```

## License

MIT
