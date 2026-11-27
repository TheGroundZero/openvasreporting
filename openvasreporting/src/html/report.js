(function () {
  "use strict";
  var doc = document;
  doc.documentElement.classList.add("js");

  var tabs = Array.prototype.slice.call(doc.querySelectorAll("[data-tab]"));
  var panels = Array.prototype.slice.call(doc.querySelectorAll("section.tab"));
  var items = Array.prototype.slice.call(doc.querySelectorAll(".vitem"));
  var cards = Array.prototype.slice.call(doc.querySelectorAll("article.vuln"));

  function showTab(id) {
    panels.forEach(function (p) { p.classList.toggle("active", p.id === id); });
    tabs.forEach(function (t) { t.setAttribute("aria-selected", String(t.getAttribute("data-tab") === id)); });
  }

  function showVuln(anchor) {
    var found = false;
    cards.forEach(function (c) {
      var on = c.id === anchor;
      c.classList.toggle("active", on);
      found = found || on;
    });
    items.forEach(function (i) { i.classList.toggle("active", i.getAttribute("href") === "#" + anchor); });
    return found;
  }

  // open a host card from a link in the vulnerability view, even if collapsed or filtered out
  function showHost(anchor) {
    var host = doc.getElementById(anchor);
    if (!host || !host.classList.contains("host")) { return false; }
    var search = doc.getElementById("host-search");
    if (host.hidden && search) {
      search.value = "";
      search.dispatchEvent(new Event("input"));
    }
    var details = host.querySelector("details");
    if (details) { details.open = true; }
    host.classList.add("flash");
    window.setTimeout(function () { host.classList.remove("flash"); }, 1500);
    window.setTimeout(function () { host.scrollIntoView({ block: "start" }); }, 0);
    return true;
  }

  function route() {
    var hash = "";
    try {
      hash = decodeURIComponent(location.hash.slice(1));
    } catch (e) {
      hash = "";  // malformed fragment such as '#%': fall back to the summary
    }
    if (/^vuln-\d+$/.test(hash) && showVuln(hash)) {
      showTab("vulnerabilities");
      var item = doc.querySelector('.vitem[href="#' + hash + '"]');
      if (item) { item.scrollIntoView({ block: "nearest" }); }
      window.scrollTo(0, 0);
    } else if (/^host-\d+$/.test(hash) && showHost(hash)) {
      showTab("hosts");
    } else if (hash === "vulnerabilities" || hash === "hosts" || hash === "summary") {
      showTab(hash);
    } else {
      showTab("summary");
    }
  }

  tabs.forEach(function (t) {
    t.addEventListener("click", function () {
      var id = t.getAttribute("data-tab");
      history.replaceState(null, "", "#" + id);
      showTab(id);
    });
  });
  window.addEventListener("hashchange", route);

  // ---- filters: free text + severity chips ----
  function setupFilter(input, chips, rows) {
    function apply() {
      var q = input ? input.value.trim().toLowerCase() : "";
      var levels = chips.filter(function (c) { return c.getAttribute("aria-pressed") === "true"; })
        .map(function (c) { return c.getAttribute("data-level"); });
      var shown = 0;
      rows.forEach(function (r) {
        var okText = !q || (r.getAttribute("data-search") || "").indexOf(q) !== -1;
        var okLevel = !chips.length || levels.indexOf(r.getAttribute("data-level")) !== -1;
        r.hidden = !(okText && okLevel);
        if (!r.hidden) { shown += 1; }
      });
      return shown;
    }
    if (input) { input.addEventListener("input", apply); }
    chips.forEach(function (c) {
      c.addEventListener("click", function () {
        c.setAttribute("aria-pressed", String(c.getAttribute("aria-pressed") !== "true"));
        apply();
      });
    });
    apply();
  }

  setupFilter(doc.getElementById("vuln-search"),
    Array.prototype.slice.call(doc.querySelectorAll("#vulnerabilities .chip")), items);
  setupFilter(doc.getElementById("host-search"),
    Array.prototype.slice.call(doc.querySelectorAll("#hosts .chip")),
    Array.prototype.slice.call(doc.querySelectorAll("article.host")));

  if (cards.length) { showVuln(cards[0].id); }
  route();
})();
