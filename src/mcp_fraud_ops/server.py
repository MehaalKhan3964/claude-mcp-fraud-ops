"""
FastAPI HTTP + Model Context Protocol (MCP) Server for Claude Agents.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from .engine import (
    MCP_TOOL_SCHEMAS,
    FraudVerdict,
    InMemorySupabaseLedger,
    MCPToolCallRequest,
    SMSWebhookPayload,
)

app = FastAPI(
    title="Claude MCP Fraud Ops Server",
    version="1.0.0",
    description="Anthropic MCP-compatible tool server + FastAPI webhook engine for real-time payment fraud detection.",
)

ledger = InMemorySupabaseLedger()


def seed_demo_transactions() -> None:
    if ledger.get_stats()["total_evaluated"] > 0:
        return
    samples = [
        SMSWebhookPayload(
            sender="3737",
            raw_message="Trx ID 8492019283. You have received Rs. 1,500.00 from 03015551234 via Easypaisa.",
            claimed_amount_pkr=1500.0,
            cashier_id="POS-HAYATABAD-01",
        ),
        SMSWebhookPayload(
            sender="+923129998877",
            raw_message="Trx ID 9918273645. You have received Rs. 4,500.00 from Ahmad via Easypaisa.",
            claimed_amount_pkr=4500.0,
            cashier_id="POS-UNI-ROAD-02",
        ),
        SMSWebhookPayload(
            sender="8558",
            raw_message="TID 7726154890. Rs. 250.00 received in your JazzCash account.",
            claimed_amount_pkr=2500.0,
            cashier_id="POS-HAYATABAD-01",
        ),
    ]
    for sample in samples:
        ledger.evaluate_payment(sample)


seed_demo_transactions()


@app.get("/mcp/tools")
def list_mcp_tools() -> dict[str, Any]:
    """Return Anthropic MCP-compatible tool manifest."""
    return {"protocol": "mcp/1.0", "tools": MCP_TOOL_SCHEMAS}


@app.post("/mcp/call")
def call_mcp_tool(req: MCPToolCallRequest) -> dict[str, Any]:
    """Execute an MCP tool call invoked by Claude or an autonomous agent."""
    if req.tool_name == "verify_payment_sms":
        payload = SMSWebhookPayload(**req.arguments)
        verdict = ledger.evaluate_payment(payload)
        return {"tool": req.tool_name, "isError": False, "content": verdict.model_dump()}
    if req.tool_name == "query_ledger_stats":
        return {"tool": req.tool_name, "isError": False, "content": ledger.get_stats()}
    if req.tool_name == "check_duplicate_tx":
        tx_id = str(req.arguments.get("tx_id", ""))
        return {
            "tool": req.tool_name,
            "isError": False,
            "content": {"tx_id": tx_id, "already_used": ledger.has_tx(tx_id)},
        }
    if req.tool_name == "list_flagged_incidents":
        return {"tool": req.tool_name, "isError": False, "content": ledger.list_incidents()}
    raise HTTPException(status_code=400, detail=f"Unknown MCP tool: {req.tool_name}")


@app.post("/api/verify", response_model=FraudVerdict)
def verify_webhook(payload: SMSWebhookPayload) -> FraudVerdict:
    return ledger.evaluate_payment(payload)


@app.get("/api/stats")
def stats() -> dict[str, Any]:
    return ledger.get_stats()


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    st = ledger.get_stats()
    incidents = ledger.list_incidents()
    rows = "".join(
        f"<tr><td><code>{inc['tx_id']}</code></td><td><b>{inc['status']}</b></td>"
        f"<td>{inc['risk_score']}/100</td><td>{inc['ai_triage_summary']}</td>"
        f"<td>{inc['latency_ms']} ms</td></tr>"
        for inc in incidents
    )
    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Claude MCP Fraud Ops Dashboard</title>
  <style>
    body {{ font-family: system-ui, sans-serif; background: #0f172a; color: #f8fafc; padding: 2rem; }}
    .cards {{ display: flex; gap: 1rem; margin-bottom: 1.5rem; }}
    .card {{ background: #1e293b; padding: 1.25rem; border-radius: 10px; flex: 1; border: 1px solid #334155; }}
    table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; }}
    th, td {{ padding: 0.85rem; text-align: left; border-bottom: 1px solid #334155; }}
    th {{ background: #0f172a; color: #38bdf8; }}
    code {{ color: #f472b6; }}
  </style>
</head>
<body>
  <h1>Claude MCP Fraud Ops &amp; Supabase Audit Server</h1>
  <p>Model Context Protocol (MCP) tool server exposing 4 structured tools for Anthropic Claude agents.</p>
  <div class="cards">
    <div class="card"><h3>Total Audited</h3><h2>{st['total_evaluated']}</h2></div>
    <div class="card"><h3>Verified Legit</h3><h2>{st['verified_count']}</h2></div>
    <div class="card"><h3>Blocked Fraud</h3><h2>{st['blocked_fraud_count']}</h2></div>
    <div class="card"><h3>Block Rate</h3><h2>{st['fraud_block_rate_pct']}%</h2></div>
  </div>
  <h2>Flagged Security Incidents</h2>
  <table>
    <thead><tr><th>Tx ID</th><th>Verdict</th><th>Risk Score</th><th>Claude MCP Triage Summary</th><th>Latency</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</body>
</html>"""
