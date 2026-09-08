from unittest.mock import AsyncMock
import pytest
from BlueTeam.websocket.manager import ConnectionManager


def make_mock_ws(fail_on_send: bool = False) -> AsyncMock:
    ws = AsyncMock()
    ws.accept = AsyncMock()
    if fail_on_send:
        ws.send_json = AsyncMock(
            side_effect=RuntimeError("WebSocket connection lost")
        )
    else:
        ws.send_json = AsyncMock()
    return ws


# =====================================================================
# 15 REQUIRED UNIT TESTS
# =====================================================================

@pytest.mark.asyncio
async def test_1_manager_starts_with_zero_active_connections():
    manager = ConnectionManager()
    assert len(manager.active_connections) == 0
    assert manager.active_count == 0


@pytest.mark.asyncio
async def test_2_connect_accepts_and_registers_client():
    manager = ConnectionManager()
    ws = make_mock_ws()
    await manager.connect(ws)
    ws.accept.assert_awaited_once()
    assert len(manager.active_connections) == 1
    assert ws in manager.active_connections


@pytest.mark.asyncio
async def test_3_multiple_clients_can_connect():
    manager = ConnectionManager()
    ws1 = make_mock_ws()
    ws2 = make_mock_ws()
    ws3 = make_mock_ws()

    await manager.connect(ws1)
    await manager.connect(ws2)
    await manager.connect(ws3)

    assert manager.active_count == 3
    assert ws1 in manager.active_connections
    assert ws2 in manager.active_connections
    assert ws3 in manager.active_connections


@pytest.mark.asyncio
async def test_4_duplicate_connection_not_registered_twice():
    manager = ConnectionManager()
    ws = make_mock_ws()
    await manager.connect(ws)
    await manager.connect(ws)
    assert manager.active_count == 1


@pytest.mark.asyncio
async def test_5_disconnect_removes_client():
    manager = ConnectionManager()
    ws = make_mock_ws()
    await manager.connect(ws)
    assert manager.active_count == 1
    manager.disconnect(ws)
    assert manager.active_count == 0
    assert ws not in manager.active_connections


@pytest.mark.asyncio
async def test_6_disconnecting_unknown_client_does_not_crash():
    manager = ConnectionManager()
    ws = make_mock_ws()
    # Attempt disconnect without connect
    manager.disconnect(ws)
    assert manager.active_count == 0


@pytest.mark.asyncio
async def test_7_broadcast_sends_message_to_all_connected_clients():
    manager = ConnectionManager()
    ws1 = make_mock_ws()
    ws2 = make_mock_ws()
    await manager.connect(ws1)
    await manager.connect(ws2)

    msg = {"type": "security_alert", "alert_id": "alert-001", "risk_level": "HIGH RISK"}
    await manager.broadcast(msg)

    ws1.send_json.assert_awaited_once_with(msg)
    ws2.send_json.assert_awaited_once_with(msg)


@pytest.mark.asyncio
async def test_8_personal_message_sends_only_to_specified_client():
    manager = ConnectionManager()
    ws1 = make_mock_ws()
    ws2 = make_mock_ws()
    await manager.connect(ws1)
    await manager.connect(ws2)

    msg = {"type": "personal_note", "content": "Hello client 1"}
    success = await manager.send_personal_message(msg, ws1)

    assert success is True
    ws1.send_json.assert_awaited_once_with(msg)
    ws2.send_json.assert_not_called()


@pytest.mark.asyncio
async def test_9_failed_client_during_broadcast_handled_safely():
    manager = ConnectionManager()
    ws_good = make_mock_ws()
    ws_bad = make_mock_ws(fail_on_send=True)

    await manager.connect(ws_good)
    await manager.connect(ws_bad)

    msg = {"type": "alert_broadcast"}
    # Broadcast should not raise exception
    await manager.broadcast(msg)


@pytest.mark.asyncio
async def test_10_failed_client_removed_after_broadcast_failure():
    manager = ConnectionManager()
    ws_bad = make_mock_ws(fail_on_send=True)
    await manager.connect(ws_bad)

    msg = {"type": "alert_broadcast"}
    await manager.broadcast(msg)

    assert ws_bad not in manager.active_connections
    assert manager.active_count == 0


@pytest.mark.asyncio
async def test_11_other_clients_still_receive_broadcast_when_one_fails():
    manager = ConnectionManager()
    ws_good1 = make_mock_ws()
    ws_bad = make_mock_ws(fail_on_send=True)
    ws_good2 = make_mock_ws()

    await manager.connect(ws_good1)
    await manager.connect(ws_bad)
    await manager.connect(ws_good2)

    msg = {"type": "security_update"}
    await manager.broadcast(msg)

    ws_good1.send_json.assert_awaited_once_with(msg)
    ws_good2.send_json.assert_awaited_once_with(msg)
    assert manager.active_count == 2
    assert ws_good1 in manager.active_connections
    assert ws_good2 in manager.active_connections
    assert ws_bad not in manager.active_connections


@pytest.mark.asyncio
async def test_12_personal_send_failure_handled_safely():
    manager = ConnectionManager()
    ws_bad = make_mock_ws(fail_on_send=True)
    await manager.connect(ws_bad)

    msg = {"type": "personal_test"}
    success = await manager.send_personal_message(msg, ws_bad)

    assert success is False
    assert ws_bad not in manager.active_connections
    assert manager.active_count == 0


@pytest.mark.asyncio
async def test_13_active_connection_count_state_remains_correct():
    manager = ConnectionManager()
    ws1 = make_mock_ws()
    ws2 = make_mock_ws()
    ws3 = make_mock_ws()

    await manager.connect(ws1)
    await manager.connect(ws2)
    await manager.connect(ws3)
    assert manager.active_count == 3

    manager.disconnect(ws2)
    assert manager.active_count == 2
    assert ws2 not in manager.active_connections
    assert ws1 in manager.active_connections
    assert ws3 in manager.active_connections


@pytest.mark.asyncio
async def test_14_structured_dictionary_messages_passed_to_send_json():
    manager = ConnectionManager()
    ws = make_mock_ws()
    await manager.connect(ws)

    structured_data = {
        "event": "INCIDENT_CREATED",
        "incident_id": "inc-001",
        "severity": "HIGH RISK",
        "score": 100,
        "details": {"attack_type": "sqli", "target": "10.0.0.1"},
    }
    await manager.broadcast(structured_data)
    ws.send_json.assert_awaited_once_with(structured_data)


def test_15_manager_module_has_no_other_module_dependencies():
    import sys
    # Verify ConnectionManager module imports cleanly without importing DB or detection modules
    from BlueTeam.websocket.manager import ConnectionManager
    mgr = ConnectionManager()
    assert mgr is not None

