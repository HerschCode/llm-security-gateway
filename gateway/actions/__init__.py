"""
Action firewall: authorizes what an agent DOES (tool calls), not only what it is told.

The rest of this gateway inspects text. Once an agent can call tools, a prompt injection that slips past
the text layers becomes an action, so this package adds a second, independent control point:

  policy.py     default-deny, per-tool capability policy (who may call what, with which arguments)
  taint.py      provenance tracking: was a write-tool argument copied from untrusted text?
  approvals.py  SQLite-backed human approval queue (separation of duties)
  firewall.py   combines policy + taint + approvals + an audit log into one decision per call
  api.py        HTTP policy-decision-point endpoints and the approval endpoints
  mcp_proxy.py  stdio MCP proxy that enforces the same firewall on `tools/call`

See docs/action-firewall.md for what is implemented, what is not (this is not CaMeL), and the measured results.
"""
