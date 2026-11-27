"""Behaviour of the HTML report in a real browser (skipped when Playwright is not installed).

Install with:  pip install -e .[test,browser] && python -m playwright install chromium
"""

import os

import pytest
from conftest import run_cli

sync_api = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def page(tmp_path_factory, request):
    out = tmp_path_factory.mktemp("html")
    from conftest import EDGE_REPORT

    res = run_cli("-i", str(EDGE_REPORT), "-o", str(out / "r"), "-f", "html")
    assert res.returncode == 0, res.stderr
    with sync_api.sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except sync_api.Error as e:  # browser binary or system libraries missing
            if os.environ.get("OPENVAS_REQUIRE_BROWSER"):
                raise
            pytest.skip(f"chromium unavailable: {str(e).splitlines()[0]}")
        pg = browser.new_page()
        pg.errors = []
        pg.on("console", lambda m: pg.errors.append(m.text) if m.type == "error" else None)
        pg.on("pageerror", lambda e: pg.errors.append(str(e)))
        pg.goto((out / "r.html").as_uri())
        yield pg
        browser.close()


def test_no_script_error_and_no_csp_violation(page):
    assert page.errors == []
    # the injected payloads stayed text: no alert dialog was raised, no extra script ran
    assert page.evaluate("document.scripts.length") == 1


def test_tabs_switch_views(page):
    page.click("[data-tab=hosts]")
    assert page.locator("#hosts").is_visible()
    assert not page.locator("#vulnerabilities").is_visible()
    page.click("[data-tab=summary]")
    assert page.locator("#summary").is_visible()


def test_search_hides_non_matching_vulnerabilities(page):
    page.click("[data-tab=vulnerabilities]")
    before = page.locator(".vitem:visible").count()
    page.fill("#vuln-search", "openssl")
    assert page.locator(".vitem:visible").count() == 1
    page.fill("#vuln-search", "")
    assert page.locator(".vitem:visible").count() == before


def test_level_chip_toggles_filter(page):
    page.click("[data-tab=vulnerabilities]")
    before = page.locator(".vitem:visible").count()
    page.click("#vulnerabilities .chip[data-level=high]")
    assert page.locator(".vitem:visible").count() == before - 1
    page.click("#vulnerabilities .chip[data-level=high]")


def test_host_link_opens_vulnerability_card(page):
    page.click("[data-tab=hosts]")
    host = page.locator("article.host[data-ip='2001:db8::1']")
    if host.locator("details").get_attribute("open") is None:  # only the 3 first hosts start expanded
        host.locator("summary").click()
    link = host.locator("a").first
    target = link.get_attribute("href").lstrip("#")
    link.click()  # routing happens on the asynchronous 'hashchange' event
    sync_api.expect(page.locator("#vulnerabilities")).to_be_visible()
    sync_api.expect(page.locator("#" + target)).to_be_visible()
    assert "libfoo" in page.locator("#" + target).inner_text()


def test_malformed_fragment_still_shows_summary(page):
    page.goto(page.url.split("#")[0] + "#%")
    sync_api.expect(page.locator("#summary")).to_be_visible()
    assert page.errors == []


def test_print_shows_only_summary(page):
    page.emulate_media(media="print")
    try:
        assert page.locator("#summary").is_visible()
        assert not page.locator("#vulnerabilities").is_visible()
        assert not page.locator("#hosts").is_visible()
    finally:
        page.emulate_media(media="screen")


def test_ip_in_vulnerability_card_opens_host(page):
    page.goto(page.url.split("#")[0] + "#vulnerabilities")
    libfoo = page.locator("article.vuln", has_text="Outdated package libfoo")
    page.locator(".vitem", has_text="Outdated package libfoo").click()
    link = libfoo.locator("a.host-link", has_text="2001:db8::1")
    target = link.get_attribute("href").lstrip("#")
    # collapse the host card (the page is shared between tests) so the link has to open it
    page.evaluate("id => { document.getElementById(id).querySelector('details').open = false; }", target)
    link.click()
    sync_api.expect(page.locator("#hosts")).to_be_visible()
    sync_api.expect(page.locator("#" + target + " table")).to_be_visible()
    assert page.locator("#" + target).get_attribute("data-ip") == "2001:db8::1"


def test_ip_link_reveals_host_hidden_by_search(page):
    page.goto(page.url.split("#")[0] + "#hosts")
    page.fill("#host-search", "192.168.1.10")
    page.goto(page.url.split("#")[0] + "#vulnerabilities")
    page.locator(".vitem", has_text="Outdated package libfoo").click()
    page.locator("article.vuln.active a.host-link").first.click()
    target = page.url.split("#")[1]
    sync_api.expect(page.locator("#" + target)).to_be_visible()
    page.fill("#host-search", "")


def test_ip_in_summary_opens_host(page):
    page.goto(page.url.split("#")[0] + "#summary")
    link = page.locator("#summary a.host-link", has_text="2001:db8::1")
    target = link.get_attribute("href").lstrip("#")
    page.evaluate("id => { document.getElementById(id).querySelector('details').open = false; }", target)
    link.click()
    sync_api.expect(page.locator("#hosts")).to_be_visible()
    sync_api.expect(page.locator("#" + target + " table")).to_be_visible()
