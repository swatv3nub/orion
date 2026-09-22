from urllib.request import build_opener

from app.tools.http import NoRedirect


def test_no_redirect_is_accepted_by_build_opener():
    opener = build_opener(NoRedirect())

    assert opener
    assert NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://example.test") is None
