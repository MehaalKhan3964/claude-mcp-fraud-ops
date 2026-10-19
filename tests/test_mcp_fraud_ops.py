from mcp_fraud_ops.engine import InMemorySupabaseLedger, MCPToolCallRequest, SMSWebhookPayload
from mcp_fraud_ops.server import call_mcp_tool, list_mcp_tools


def test_legitimate_easypaisa_sms_passes() -> None:
    ledger = InMemorySupabaseLedger()
    payload = SMSWebhookPayload(
        sender="3737",
        raw_message="Trx ID 1234567890. You have received Rs. 2,000.00 from 03001112233 via Easypaisa.",
        claimed_amount_pkr=2000.0,
    )
    verdict = ledger.evaluate_payment(payload)
    assert verdict.status == "VERIFIED"
    assert verdict.risk_score == 0
    assert verdict.parsed.tx_id == "1234567890"


def test_spoofed_sender_number_is_blocked() -> None:
    ledger = InMemorySupabaseLedger()
    payload = SMSWebhookPayload(
        sender="+923331234567",
        raw_message="Trx ID 9876543210. You have received Rs. 5,000.00 via Easypaisa.",
        claimed_amount_pkr=5000.0,
    )
    verdict = ledger.evaluate_payment(payload)
    assert verdict.status == "BLOCKED_FRAUD"
    assert verdict.risk_score >= 60


def test_replay_attack_same_tid_is_blocked() -> None:
    ledger = InMemorySupabaseLedger()
    payload = SMSWebhookPayload(
        sender="8558",
        raw_message="TID 5556667778. Rs. 1,200.00 received in your JazzCash account.",
        claimed_amount_pkr=1200.0,
    )
    first = ledger.evaluate_payment(payload)
    assert first.status == "VERIFIED"

    replay = ledger.evaluate_payment(payload)
    assert replay.status == "BLOCKED_FRAUD"
    assert any("Replay attack" in r for r in replay.reasons)


def test_amount_tampering_is_blocked() -> None:
    ledger = InMemorySupabaseLedger()
    payload = SMSWebhookPayload(
        sender="3737",
        raw_message="Trx ID 4443332221. You have received Rs. 150.00 via Easypaisa.",
        claimed_amount_pkr=1500.0,
    )
    verdict = ledger.evaluate_payment(payload)
    assert verdict.status == "BLOCKED_FRAUD"


def test_mcp_tool_manifest_and_invocation() -> None:
    manifest = list_mcp_tools()
    assert manifest["protocol"] == "mcp/1.0"
    assert len(manifest["tools"]) == 4

    res = call_mcp_tool(MCPToolCallRequest(tool_name="query_ledger_stats", arguments={}))
    assert res["isError"] is False
    assert res["content"]["total_evaluated"] >= 3
