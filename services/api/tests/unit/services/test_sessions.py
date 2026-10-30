from reconix_api.services import sessions


def test_actor_is_the_os_user_at_the_host(monkeypatch):
    monkeypatch.setattr(sessions.getpass, "getuser", lambda: "vanneth")
    monkeypatch.setattr(sessions.socket, "gethostname", lambda: "kshrd-laptop")
    assert sessions.local_actor() == "vanneth@kshrd-laptop"


def test_actor_falls_back_when_the_os_has_no_user_name(monkeypatch):
    def no_user() -> str:
        raise OSError("no user name")

    monkeypatch.setattr(sessions.getpass, "getuser", no_user)
    monkeypatch.setattr(sessions.socket, "gethostname", lambda: "kshrd-laptop")
    assert sessions.local_actor() == "operator@kshrd-laptop"


def test_actor_fits_the_by_columns(monkeypatch):
    monkeypatch.setattr(sessions.getpass, "getuser", lambda: "u" * 80)
    monkeypatch.setattr(sessions.socket, "gethostname", lambda: "h" * 80)
    assert len(sessions.local_actor()) == sessions.MAX_ACTOR
