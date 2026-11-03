// Mooring site: OS detection, live GitHub data, feature filter, screenshot lightbox.
// No dependencies. Everything degrades to the static HTML when JS or the API is unavailable.
(function () {
  "use strict";

  var REPO = "yyasar21/Mooring";
  var API = "https://api.github.com/repos/" + REPO;
  var RELEASES_PAGE = "https://github.com/" + REPO + "/releases";
  var CACHE_MS = 10 * 60 * 1000; // unauthenticated API limit is 60 requests per hour per IP

  var $ = function (sel, root) { return (root || document).querySelector(sel); };
  var $$ = function (sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); };

  // ---------- OS detection ----------
  var OS_NAMES = { macos: "macOS", windows: "Windows", linux: "Linux" };

  function detectOs() {
    var p = "";
    try {
      p = ((navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || "") + " " + navigator.userAgent;
    } catch (e) { return null; }
    if (/android|iphone|ipad|ipod/i.test(p)) return null;
    if (/mac/i.test(p)) return "macos";
    if (/win/i.test(p)) return "windows";
    if (/linux|x11|cros/i.test(p)) return "linux";
    return null;
  }

  var os = detectOs();
  if (os) {
    var cta = $("#cta-download");
    cta.textContent = "Download for " + OS_NAMES[os];
    cta.setAttribute("href", "#os-" + os);
    var card = $("#os-" + os);
    card.classList.add("is-you");
    var tag = document.createElement("span");
    tag.className = "you";
    tag.textContent = "your system";
    $("h3", card).appendChild(tag);
    // put the visitor's platform first
    card.parentNode.insertBefore(card, card.parentNode.firstElementChild);
  }

  // ---------- cached fetch ----------
  function cacheGet(key) {
    try {
      var raw = sessionStorage.getItem(key);
      if (!raw) return null;
      var v = JSON.parse(raw);
      return Date.now() - v.t < CACHE_MS ? v.d : null;
    } catch (e) { return null; }
  }
  function cacheSet(key, data) {
    try { sessionStorage.setItem(key, JSON.stringify({ t: Date.now(), d: data })); } catch (e) { /* private mode */ }
  }
  function getJson(url) {
    var hit = cacheGet(url);
    if (hit) return Promise.resolve(hit);
    if (!window.fetch) return Promise.reject(new Error("no fetch"));
    return fetch(url, { headers: { Accept: "application/vnd.github+json" } }).then(function (r) {
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.json();
    }).then(function (d) { cacheSet(url, d); return d; });
  }

  // ---------- stars ----------
  function compact(n) {
    if (n >= 10000) return Math.round(n / 1000) + "k";
    if (n >= 1000) return (n / 1000).toFixed(1).replace(/\.0$/, "") + "k";
    return String(n);
  }
  getJson(API).then(function (repo) {
    var n = repo && typeof repo.stargazers_count === "number" ? repo.stargazers_count : null;
    if (n === null) throw new Error("no count");
    var el = $("#star-count");
    el.textContent = compact(n);
    el.setAttribute("aria-label", n + " stars on GitHub");
    el.hidden = false;
    $("#tm-stars").textContent = n.toLocaleString("en-US");
  }).catch(function () {
    $("#tm-stars").textContent = "on GitHub";
  });

  // ---------- releases ----------
  // Asset names come from docs/release.md, e.g. Mooring_0.1.0_universal.dmg, Mooring-0.1.0-1.x86_64.rpm.
  var KINDS = [
    { kind: "dmg", re: /\.dmg$/i },
    { kind: "pkg", re: /\.pkg$/i },
    { kind: "exe", re: /-setup\.exe$/i },
    { kind: "msi", re: /\.msi$/i },
    { kind: "deb", re: /\.deb$/i },
    { kind: "rpm", re: /\.rpm$/i },
    { kind: "appimage", re: /\.appimage$/i }
  ];
  function arch(name, kind) {
    if (/universal/i.test(name)) return "Universal";
    var arm = /(aarch64|arm64)/i.test(name);
    if (kind === "dmg" || kind === "pkg") return arm ? "Apple silicon" : "Intel";
    return arm ? "arm64" : "x86_64";
  }
  var ARCH_ORDER = ["Universal", "Apple silicon", "Intel", "x86_64", "arm64"];
  function archRank(a) { var i = ARCH_ORDER.indexOf(a); return i < 0 ? 99 : i; }
  function mb(bytes) { return (bytes / 1048576).toFixed(0) + " MB"; }

  function pickRelease(list) {
    var usable = (list || []).filter(function (r) { return !r.draft; });
    usable.sort(function (a, b) { return Date.parse(b.published_at || 0) - Date.parse(a.published_at || 0); });
    var stable = usable.filter(function (r) { return !r.prerelease; });
    return stable[0] || usable[0] || null;
  }

  function renderRelease(rel) {
    var status = $("#dl-status");
    var tm = $("#tm-release");
    if (!rel) {
      status.textContent = "No release has been published yet. The first one will be v0.1.0. Until then, build from source with the build guide below.";
      tm.textContent = "none yet, pre-release";
      tm.setAttribute("data-tone", "hot");
      return;
    }
    var label = rel.tag_name + (rel.prerelease ? " (pre-release)" : "");
    var date = rel.published_at ? new Date(rel.published_at).toLocaleDateString("en-GB", { year: "numeric", month: "short", day: "numeric" }) : "";
    status.textContent = "";
    status.appendChild(document.createTextNode("Latest: "));
    var a = document.createElement("a");
    a.className = "link";
    a.href = rel.html_url || RELEASES_PAGE;
    a.textContent = label;
    status.appendChild(a);
    status.appendChild(document.createTextNode(
      (date ? ", published " + date + "." : ".") +
      (rel.prerelease ? " This is a pre-release: expect rough edges and keep your current tool alongside it." : "")
    ));
    tm.textContent = label;
    if (rel.prerelease) tm.setAttribute("data-tone", "hot");

    var assets = rel.assets || [];
    KINDS.forEach(function (k) {
      var li = $('.assets li[data-kind="' + k.kind + '"]');
      if (!li) return;
      var matches = assets.filter(function (x) { return k.re.test(x.name) && !/\.sig$/i.test(x.name); })
        .map(function (x) { return { x: x, arch: arch(x.name, k.kind) }; })
        .sort(function (p, q) { return archRank(p.arch) - archRank(q.arch); });
      if (!matches.length) {
        var none = $("span", li);
        if (none && !$(".none", li)) {
          var em = document.createElement("small");
          em.className = "none";
          em.textContent = "not in this release";
          none.appendChild(em);
        }
        return;
      }
      var title = $("span", li).textContent;
      li.textContent = "";
      li.classList.add("has-links");
      matches.forEach(function (m) {
        var link = document.createElement("a");
        link.href = m.x.browser_download_url;
        link.rel = "nofollow";
        var t = document.createElement("span");
        t.textContent = title + ", " + m.arch;
        var s = document.createElement("small");
        s.textContent = (k.kind === "appimage" ? ".AppImage" : "." + k.kind) + "  " + mb(m.x.size);
        link.appendChild(t);
        link.appendChild(s);
        li.appendChild(link);
      });
    });
  }

  getJson(API + "/releases?per_page=10").then(function (list) {
    renderRelease(pickRelease(list));
  }).catch(function () {
    var status = $("#dl-status");
    status.textContent = "";
    status.appendChild(document.createTextNode("Could not reach the GitHub API. See all builds on the "));
    var a = document.createElement("a");
    a.className = "link";
    a.href = RELEASES_PAGE;
    a.textContent = "Releases page";
    status.appendChild(a);
    status.appendChild(document.createTextNode("."));
    $("#tm-release").textContent = "see Releases";
  });

  // ---------- feature filter ----------
  var buttons = $$(".filter button");
  buttons.forEach(function (b) {
    b.addEventListener("click", function () {
      var f = b.getAttribute("data-filter");
      buttons.forEach(function (o) { o.setAttribute("aria-pressed", String(o === b)); });
      $$("#feature-groups li").forEach(function (li) {
        li.hidden = f !== "all" && li.getAttribute("data-status") !== f;
      });
      $$("#feature-groups .fgroup").forEach(function (g) {
        g.hidden = !$("li:not([hidden])", g);
      });
    });
  });

  // ---------- lightbox ----------
  var dlg = $("#lightbox");
  var shots = $$("#gallery button");
  var current = 0;
  function show(i) {
    current = (i + shots.length) % shots.length;
    var b = shots[current];
    var img = $("img", b);
    $("#lightbox-img").src = b.getAttribute("data-full");
    $("#lightbox-img").alt = img.alt;
    $("#lightbox-cap").textContent = b.parentNode.querySelector("p").textContent + " (" + (current + 1) + " of " + shots.length + ")";
  }
  if (dlg && typeof dlg.showModal === "function") {
    shots.forEach(function (b, i) {
      b.addEventListener("click", function () { show(i); dlg.showModal(); $("#lightbox-close").focus(); });
    });
    $$("[data-step]", dlg).forEach(function (b) {
      b.addEventListener("click", function () { show(current + Number(b.getAttribute("data-step"))); });
    });
    $("#lightbox-close").addEventListener("click", function () { dlg.close(); });
    dlg.addEventListener("click", function (e) { if (e.target === dlg) dlg.close(); });
    dlg.addEventListener("keydown", function (e) {
      if (e.key === "ArrowRight") show(current + 1);
      if (e.key === "ArrowLeft") show(current - 1);
    });
    dlg.addEventListener("close", function () { shots[current].focus(); });
  } else {
    // no <dialog>: open the full image directly
    shots.forEach(function (b) {
      b.addEventListener("click", function () { window.location.href = b.getAttribute("data-full"); });
    });
  }
})();
