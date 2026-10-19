# claude-mcp-fraud-ops

A FastAPI service and Model Context Protocol (MCP) tool server for verifying Easypaisa (`3737`) and JazzCash (`8558`) SMS payment receipts. It checks incoming receipts for spoofed sender numbers, reused transaction IDs, and edited payment amounts before logging results to a Supabase table.

## Features

- Exposes 4 MCP tools at `/mcp/tools` and `/mcp/call`:
  - `verify_payment_sms`: Parses raw SMS text and checks sender shortcode, transaction ID uniqueness, and amount match.
  - `query_ledger_stats`: Returns total checked, verified, and blocked payment counts.
  - `check_duplicate_tx`: Checks if a transaction ID (`TID` or `Trx ID`) was already used.
  - `list_flagged_incidents`: Lists blocked payment attempts with reasons and risk scores.
- Includes a small web dashboard at `GET /` showing recent flagged transactions and latency.

## Usage

```bash
# Run tests
pytest

# Start the server
uvicorn mcp_fraud_ops.server:app --reload --app-dir src
```
