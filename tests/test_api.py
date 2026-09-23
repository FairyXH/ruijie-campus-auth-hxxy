from ruijie_hxxy import RuijieClient


def test_initial_status_is_json_friendly() -> None:
    client = RuijieClient("student", "secret", log_file=None)

    status = client.status()

    assert status["state"] == "idle"
    assert status["authenticated"] is False
    assert status["interface"] is None
    assert status["logs"] == []
    assert client.stat() == status
