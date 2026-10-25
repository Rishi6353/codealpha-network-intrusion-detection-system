from dashboard.app import build_dashboard_data


def test_empty_events():
    data = build_dashboard_data([])

    assert data["total_events"] == 0
    assert data["alert_count"] == 0
    assert data["unique_sources"] == 0
    assert data["event_counts"] == {}
    assert data["recent_alerts"] == []


def test_event_counts_and_unique_sources():
    events = [
        {"event_type": "dns", "src_ip": "192.168.1.10"},
        {"event_type": "flow", "src_ip": "192.168.1.10"},
        {"event_type": "dns", "src_ip": "192.168.1.20"},
    ]

    data = build_dashboard_data(events)

    assert data["total_events"] == 3
    assert data["event_counts"] == {"dns": 2, "flow": 1}
    assert data["unique_sources"] == 2


def test_alert_details_and_severity():
    events = [
        {
            "event_type": "alert",
            "timestamp": "2026-10-25T12:00:00+00:00",
            "src_ip": "192.168.1.10",
            "dest_ip": "192.168.1.20",
            "proto": "TCP",
            "alert": {
                "severity": 2,
                "signature": "Test alert",
            },
        }
    ]

    data = build_dashboard_data(events)

    assert data["alert_count"] == 1
    assert data["severity_counts"] == {"2": 1}
    assert data["recent_alerts"][0]["signature"] == "Test alert"
    assert data["recent_alerts"][0]["src_ip"] == "192.168.1.10"


def test_missing_optional_fields():
    data = build_dashboard_data([{"event_type": "alert"}])

    assert data["total_events"] == 1
    assert data["alert_count"] == 1
    assert data["recent_alerts"][0]["signature"] == "Unknown alert"
    assert data["recent_alerts"][0]["src_ip"] == "—"
    assert data["severity_counts"] == {}


def test_unknown_event_type():
    data = build_dashboard_data([{}])

    assert data["total_events"] == 1
    assert data["event_counts"] == {"unknown": 1}
