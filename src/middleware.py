"""
FastAPI application: OIDC authentication, provisioning, and reverse proxy.

Request lifecycle
-----------------
Special routes (handled before the catch-all):
  GET /healthz               → liveness probe
  GET /readyz                → readiness probe (checks CS + OIDC provider)
  GET /auth/callback         → OIDC authorization code callback
  GET /auth/logout           → clear session cookie, redirect to /
  GET /auth/me               → return current user identity (debug)
  POST /admin/cache/clear    → drop provisioning cache
  POST /admin/reconcile      → trigger manual reconciliation

All other requests:
  1. Read identity from signed session cookie.
  2. If no valid session → redirect browser to IdP (OIDC auth code flow).
  3. Cache check: if (sub + groups_hash) is cached → skip provisioning.
  4. Run provisioner to ensure CloudStack objects are up-to-date.
  5. Proxy request to CloudStack upstream.
"""
from __future__ import annotations

import logging
import secrets
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse

from .cache import BaseCache
from .cloudstack_client import CloudStackClient, CloudStackError
from .group_parser import parse_groups, ParsedGroups, PermLevel
from .models import AppConfig, CacheEntry, OidcIdentity, UiConfig
from .oidc_auth import OidcAuthError, OidcProvider
from .permission import check_permission
from .provisioner import Provisioner
from .reconciler import Reconciler

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Login page generator
# ---------------------------------------------------------------------------

def _make_login_page(next_path: str = "/client/", error: str = "") -> str:
    """Return the branded 'Sign in with Microsoft' login page.

    error can be 'loop' (too many attempts) or 'session' (session expired).
    """
    import html as _html
    safe_next = _html.escape(next_path or "/client/")
    next_qs = f"?next={safe_next}" if safe_next not in ("/", "") else ""
    if error == "loop":
        _error_html = """<div class='err'>⚠️ Too many sign-in attempts &mdash; there may be a configuration issue. Please try again or contact your administrator.</div>"""
    elif error == "session":
        _error_html = """<div class='err'>⚠️ Your session has expired. Please sign in again.</div>"""
    else:
        _error_html = ""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Sign in to CloudStack</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
          background:#f0f2f5;min-height:100vh;display:flex;
          align-items:center;justify-content:center}}
    .card{{background:#fff;border-radius:8px;
           box-shadow:0 2px 12px rgba(0,0,0,.1);
           padding:48px 40px;max-width:400px;width:100%;text-align:center}}
    .cs-icon{{font-size:48px;margin-bottom:16px}}
    h1{{font-size:22px;font-weight:600;color:#1a1a1a;margin-bottom:8px}}
    p{{color:#666;font-size:14px;margin-bottom:32px}}
    .btn{{display:inline-flex;align-items:center;justify-content:center;gap:10px;
          background:#0078d4;color:#fff;border:none;border-radius:4px;
          padding:12px 24px;font-size:15px;font-weight:500;cursor:pointer;
          text-decoration:none;transition:background 0.2s;min-width:220px}}
    .btn:hover{{background:#106ebe}}
    .btn.loading{{background:#5a9fd4;cursor:not-allowed;pointer-events:none}}
    .spinner-sm{{width:18px;height:18px;border:2px solid rgba(255,255,255,.4);
                 border-top-color:#fff;border-radius:50%;flex-shrink:0;
                 animation:spin-sm 0.7s linear infinite}}
    @keyframes spin-sm{{to{{transform:rotate(360deg)}}}}
    .err{{background:#fff0f0;border-left:3px solid #e00;border-radius:4px;
          padding:10px 14px;font-size:13px;color:#c00;margin-bottom:20px;text-align:left}}
  </style>
</head>
<body>
  <div class="card">
    <div class="cs-icon">&#9729;&#65039;</div>
    <h1>Sign in to CloudStack</h1>
    {_error_html}
    <p>Use your organisation account to continue.</p>
    <a class="btn" id="signinBtn" href="/auth/start{next_qs}">
      <svg id="msLogo" width="20" height="20" viewBox="0 0 21 21" xmlns="http://www.w3.org/2000/svg">
        <rect x="1" y="1" width="9" height="9" fill="#f25022"/>
        <rect x="11" y="1" width="9" height="9" fill="#7fba00"/>
        <rect x="1" y="11" width="9" height="9" fill="#00a4ef"/>
        <rect x="11" y="11" width="9" height="9" fill="#ffb900"/>
      </svg>
      <span id="signinText">Sign in with Microsoft</span>
    </a>
  </div>
  <script>
  (function(){{
    var btn = document.getElementById('signinBtn');
    var logo = document.getElementById('msLogo');
    var txt = document.getElementById('signinText');
    btn.addEventListener('click', function() {{
      btn.classList.add('loading');
      logo.style.display = 'none';
      txt.textContent = 'Redirecting…';
      var sp = document.createElement('span');
      sp.className = 'spinner-sm';
      btn.insertBefore(sp, txt);
    }});
  }})();
  </script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Static HTML for the access-denied page
# ---------------------------------------------------------------------------

_DENIED_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Access Denied &#8212; CloudStack Gateway</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{
      font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
      background:#f0f2f5;min-height:100vh;
      display:flex;align-items:center;justify-content:center;color:#333
    }}
    .card{{
      background:#fff;border-radius:8px;
      box-shadow:0 2px 12px rgba(0,0,0,.1);
      padding:48px 40px;max-width:560px;width:100%;text-align:center
    }}
    .icon{{font-size:56px;margin-bottom:20px}}
    h1{{font-size:22px;font-weight:600;margin-bottom:10px;color:#1a1a2e}}
    .badge{{
      display:inline-block;background:#f0f2f5;border-radius:20px;
      padding:5px 16px;font-size:13px;color:#555;margin-bottom:22px
    }}
    p{{line-height:1.6;color:#666;margin-bottom:14px}}
    code{{background:#f5f5f5;border-radius:4px;padding:2px 6px;font-size:12px;color:#c0392b}}
    .reason{{background:#fff8e1;border-left:3px solid #f59e0b;padding:10px 14px;
             border-radius:4px;text-align:left;font-size:13px;color:#555;margin-bottom:20px}}
    .debug{{
      background:#f8f9fa;border:1px solid #dee2e6;border-radius:6px;
      padding:14px 16px;text-align:left;margin-top:20px
    }}
    .debug summary{{font-size:12px;font-weight:600;color:#495057;cursor:pointer;margin-bottom:6px}}
    .debug pre{{
      font-size:11px;color:#495057;white-space:pre-wrap;word-break:break-all;
      margin:0;max-height:200px;overflow-y:auto
    }}
    .btn{{
      display:inline-block;margin-top:18px;padding:10px 28px;
      background:#2563eb;color:#fff;border-radius:6px;text-decoration:none;
      font-size:14px;font-weight:500
    }}
    .btn:hover{{background:#1d4ed8}}
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">&#128683;</div>
    <h1>Access Denied</h1>
    <div class="badge">&#9993; {email}</div>
    <p>You have successfully signed in, but your account has not been
    assigned any CloudStack access roles.</p>
    <div class="reason">
      Ask your administrator to assign you a <code>CS_*</code> group
      (e.g.&nbsp;<code>CS_ROOT_READONLY</code>) and ensure the group name
      is emitted in the <code>{groups_claim}</code> claim, then sign in again.
    </div>
    <p style="font-size:12px;color:#999">Signed in as: {username} &nbsp;|&nbsp; sub: {sub}</p>
    <details class="debug">
      <summary>&#128269; Token claims received (for troubleshooting)</summary>
      <pre>{claims_json}</pre>
    </details>
    <a href="/auth/logout" class="btn">Sign out &amp; try again</a>
  </div>
</body>
</html>
"""

# ---------------------------------------------------------------------------
# OIDC login bridge page
# ---------------------------------------------------------------------------
#
# Problem: the CloudStack Vue SPA's GetInfo() action only resolves its Promise
# when EITHER (a) primate__APIS is already in localStorage ("hasAuth" path), OR
# (b) the Vuex loginFlag is true (set by the SPA's own login form).
#
# When the user logs in via our OIDC gateway, neither condition holds — we
# bypass the SPA login form entirely.  Result: GetInfo() hangs forever, the Vue
# Router never calls next(), NProgress bar stays stuck.
#
# Fix: instead of a bare 302 redirect after the OIDC callback, serve a small
# HTML page that:
#  1. Reads the sessionkey from the browser cookie (it was just set).
#  2. Fetches /client/api/?command=listApis (same-origin, cookies forwarded).
#  3. Builds the apis dict in the exact format GetInfo() expects.
#  4. Writes it to localStorage as primate__APIS (vue-web-storage format:
#     {"value": <apis>, "expire": 0}).
#  5. Also writes primate__Access-Token with a 24 h TTL.
#  6. Redirects to the original target URL.
#
# After this, primate__APIS is non-empty → hasAuth=true → GetInfo() takes the
# "cached APIs" branch, calls listUsers to validate the session, resolves, and
# the router completes navigation normally.
#
_BRIDGE_PAGE = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Signing in\u2026</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
          background:#f0f2f5;min-height:100vh;display:flex;align-items:center;
          justify-content:center;color:#333}}
    .card{{background:#fff;border-radius:8px;box-shadow:0 2px 12px rgba(0,0,0,.1);
           padding:48px 40px;max-width:340px;width:100%;text-align:center}}
    .spinner{{width:32px;height:32px;border:3px solid #1890ff;
              border-top-color:transparent;border-radius:50%;
              animation:spin 0.8s linear infinite;margin:0 auto 20px}}
    @keyframes spin{{to{{transform:rotate(360deg)}}}}
    p{{color:#666;font-size:14px}}
  </style>
</head>
<body>
  <div class="card">
    <div class="spinner"></div>
    <p>Signing in to CloudStack\u2026</p>
  </div>
  <script>
  (function(){{
    var REDIRECT = {redirect_to_js};
    var PREFIX   = 'primate__';

    function getCookie(name) {{
      var m = document.cookie.match('(?:^|;\\s*)' + name + '=([^;]*)');
      return m ? decodeURIComponent(m[1]) : null;
    }}

    /* vue-web-storage v6 set(key,value) just JSON.stringify-encodes the
       value and writes PREFIX+key — no TTL wrapper.  Matching that format
       exactly is critical: get(key) does JSON.parse of the stored string,
       so wrapping in {{value,expire}} would cause the whole object to be
       returned instead of the plain token string.                          */
    function lsSet(key, value) {{
      try {{
        localStorage.setItem(PREFIX + key, JSON.stringify(value));
      }} catch(e) {{}}
    }}

    function lsGet(key) {{
      try {{
        var raw = localStorage.getItem(PREFIX + key);
        return raw ? JSON.parse(raw) : null;
      }} catch(e) {{ return null; }}
    }}

    var redirected = false;
    function done() {{
      if (redirected) return;
      redirected = true;
      clearTimeout(fallback);
      /* Restore the deep-link hash the user was on before the login redirect.
         Saved as a short-lived cookie so it survives the cross-origin OIDC
         round-trip (sessionStorage is cleared by Firefox on cross-origin nav).  */
      var dest = REDIRECT;
      try {{
        var m = document.cookie.match(/(?:^|;\s*)_gw_hash=([^;]*)/);
        var savedHash = m ? decodeURIComponent(m[1]) : '';
        document.cookie = '_gw_hash=; path=/; samesite=lax; max-age=0';
        if (savedHash && savedHash !== '#' && savedHash !== '#/' &&
            savedHash.indexOf('#/user/login') === -1 && dest.indexOf('#') === -1) {{
          dest = dest.replace(/\/$/, '') + savedHash;
        }}
      }} catch(e) {{}}
      window.location.href = dest;
    }}

    /* 30-second hard timeout — redirect regardless of API call status.
       listApis can be slow on busy servers; we MUST give it enough time.  */
    var fallback = setTimeout(done, 30000);

    var sk = getCookie('sessionkey');
    if (!sk) {{ done(); return; }}

    /* Store the raw session token string — $localStorage.get('Access-Token')
       will JSON.parse it back to the plain string.                        */
    lsSet('Access-Token', sk);

    /* Both calls fire in parallel.
       listCapabilities: fast (~200 ms), seeds VUE_VERSION only.
         bootstrap.js does: if ($localStorage.get('VUE_VERSION') !== app.version)
           {{ localStorage.clear() }}  — wiping APIS before GetInfo() runs.
         We MUST seed this value but it does NOT trigger the redirect.
       listApis: slow (can exceed 20 s), seeds APIS so the SPA's GetInfo
         sees hasAuth=true and takes the fast-path instead of hanging.
         THE REDIRECT FIRES ONLY AFTER listApis COMPLETES (or the fallback).  */
    var apiBase = '/client/api/?response=json&sessionkey=' + encodeURIComponent(sk);

    /* Seed VUE_VERSION — does NOT redirect. */
    fetch(apiBase + '&command=listCapabilities')
      .then(function(r) {{ return r.json(); }})
      .then(function(data) {{
        var cap = ((data.listcapabilitiesresponse || {{}}).capability) || {{}};
        var ver = cap.cloudstackversion;
        if (ver) {{ lsSet('VUE_VERSION', ver); }}
      }})
      .catch(function() {{}});

    /* Seed APIS — redirect ONLY when this completes (or fails). */
    fetch(apiBase + '&command=listApis')
      .then(function(r) {{ return r.json(); }})
      .then(function(data) {{
        var list = (data.listapisresponse || {{}}).api || [];
        var apis = {{}};
        for (var i = 0; i < list.length; i++) {{
          var a = list[i];
          apis[a.name] = {{
            params: a.params,
            response: a.response,
            isasync: a.isasync,
            since: a.since,
            description: a.description
          }};
        }}
        if (Object.keys(apis).length > 0) {{ lsSet('APIS', apis); }}
        done();
      }})
      .catch(done);
  }})();
  </script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Session-refresh page — served when a CS session expires mid-flight.
# Unlike the login bridge page, this one is served as a JSON-like response
# that the SPA's axios interceptor would have seen.  But since it targets
# full-page XHR calls (listUsers 401), we return HTML and rely on the
# browser redirecting.  The page reuses _BRIDGE_PAGE logic: fetches
# listApis with the new sessionkey cookie (already set on this response),
# updates localStorage, then redirects back to the same page.
# ---------------------------------------------------------------------------
_REFRESH_PAGE = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Refreshing session\u2026</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
          background:#f0f2f5;min-height:100vh;display:flex;align-items:center;
          justify-content:center;color:#333}}
    .card{{background:#fff;border-radius:8px;box-shadow:0 2px 12px rgba(0,0,0,.1);
           padding:48px 40px;max-width:340px;width:100%;text-align:center}}
    .spinner{{width:32px;height:32px;border:3px solid #1890ff;
              border-top-color:transparent;border-radius:50%;
              animation:spin 0.8s linear infinite;margin:0 auto 20px}}
    @keyframes spin{{to{{transform:rotate(360deg)}}}}
    p{{color:#666;font-size:14px}}
  </style>
</head>
<body>
  <div class="card">
    <div class="spinner"></div>
    <p>Refreshing session\u2026</p>
  </div>
  <script>
  (function(){{
    var REDIRECT = {redirect_to_js};
    var PREFIX   = 'primate__';

    function getCookie(name) {{
      var m = document.cookie.match('(?:^|;\\s*)' + name + '=([^;]*)');
      return m ? decodeURIComponent(m[1]) : null;
    }}

    function lsSet(key, value) {{
      try {{
        localStorage.setItem(PREFIX + key, JSON.stringify(value));
      }} catch(e) {{}}
    }}

    function lsGet(key) {{
      try {{
        var raw = localStorage.getItem(PREFIX + key);
        return raw ? JSON.parse(raw) : null;
      }} catch(e) {{ return null; }}
    }}

    var redirected = false;
    function done() {{
      if (redirected) return;
      redirected = true;
      clearTimeout(fallback);
      var dest = REDIRECT;
      try {{
        var m = document.cookie.match(/(?:^|;\s*)_gw_hash=([^;]*)/);
        var savedHash = m ? decodeURIComponent(m[1]) : '';
        document.cookie = '_gw_hash=; path=/; samesite=lax; max-age=0';
        if (savedHash && savedHash !== '#' && savedHash !== '#/' &&
            savedHash.indexOf('#/user/login') === -1 && dest.indexOf('#') === -1) {{
          dest = dest.replace(/\/$/, '') + savedHash;
        }}
      }} catch(e) {{}}
      window.location.href = dest;
    }}

    var fallback = setTimeout(done, 3000);

    var sk = getCookie('sessionkey');
    if (!sk) {{ done(); return; }}
    lsSet('Access-Token', sk);

    var apiBase = '/client/api/?response=json&sessionkey=' + encodeURIComponent(sk);

    fetch(apiBase + '&command=listCapabilities')
      .then(function(r) {{ return r.json(); }})
      .then(function(data) {{
        var cap = ((data.listcapabilitiesresponse || {{}}).capability) || {{}};
        var ver = cap.cloudstackversion;
        if (ver) {{ lsSet('VUE_VERSION', ver); }}
        done();
      }})
      .catch(done);

    fetch(apiBase + '&command=listApis')
      .then(function(r) {{ return r.json(); }})
      .then(function(data) {{
        var list = (data.listapisresponse || {{}}).api || [];
        var apis = {{}};
        for (var i = 0; i < list.length; i++) {{
          var a = list[i];
          apis[a.name] = {{params:a.params,response:a.response,isasync:a.isasync,since:a.since,description:a.description}};
        }}
        if (Object.keys(apis).length > 0) {{ lsSet('APIS', apis); }}
      }})
      .catch(function() {{}});
  }})();
  </script>
</body>
</html>
"""

# ---------------------------------------------------------------------------
# Hop-by-hop headers that must not be forwarded to the upstream
_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host",
})


# ---------------------------------------------------------------------------
# Role-type helper
# ---------------------------------------------------------------------------

def _get_role_type(parsed: ParsedGroups) -> str:
    """Return the canonical role-type string for a ParsedGroups instance.

    Used to key into ``ui.hide_commands`` / ``ui.hide_selectors``.
    Possible return values: ROOT_ADMIN | ADMIN | OPERATIONS | READONLY | USER
    """
    if parsed.is_root_admin:
        return "ROOT_ADMIN"
    if any(da.level == PermLevel.ADMIN for da in parsed.domain_access):
        return "ADMIN"
    if any(da.level == PermLevel.OPERATIONS for da in parsed.domain_access):
        return "OPERATIONS"
    if any(da.level == PermLevel.READONLY for da in parsed.domain_access):
        return "READONLY"
    return "USER"


# ---------------------------------------------------------------------------
# Plugin page JS template
# ---------------------------------------------------------------------------
# Placeholder /*PLUGINS_JSON*/ is replaced at render time via str.replace().
# Written as a plain Python string (not an f-string) so JavaScript curly
# braces need no escaping.

_PLUGIN_JS_TMPL = """\
<script>
/* \u2500\u2500 OIDCGW Plugin system \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
 * Injects custom pages into the CS SPA sidebar.  Each plugin can render
 * an iframe, raw HTML, or a fetched JSON table (api_src).
 * \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500 */
(function() {
  var PLUGINS = /*PLUGINS_JSON*/;
  if (!PLUGINS.length) return;
  function _E(s) {
    return String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;')
      .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }
  /* Overlay element */
  var _ov = document.createElement('div');
  _ov.id = 'gw-plugin-ov';
  _ov.style.cssText = 'display:none;position:fixed;top:64px;bottom:0;right:0;'
    + 'z-index:9000;background:#f0f2f5;overflow:auto;box-sizing:border-box;transition:left .2s;';
  document.body.appendChild(_ov);
  function _syncLeft() {
    var s = document.querySelector('.ant-layout-sider');
    _ov.style.left = (s ? s.offsetWidth : 200) + 'px';
  }
  /* Spinner CSS */
  var _sc = document.createElement('style');
  _sc.textContent = '#gw-plugin-ov .gw-spin{display:block;width:32px;height:32px;'
    + 'border:3px solid #1890ff;border-top-color:transparent;border-radius:50%;'
    + 'animation:gwspin .8s linear infinite;margin:48px auto}'
    + '@keyframes gwspin{to{transform:rotate(360deg)}}';
  document.head.appendChild(_sc);
  /* Hash routing */
  function _plug4hash(h) {
    for (var i = 0; i < PLUGINS.length; i++) {
      var ph = PLUGINS[i].hash;
      if (h === ph || h.startsWith(ph + '?')) return PLUGINS[i];
    }
    return null;
  }
  function _updNav() {
    var nb = document.getElementById('gw-nav-plugins');
    if (!nb) return;
    var h = window.location.hash;
    Array.from(nb.querySelectorAll('[data-gw-ph]')).forEach(function(el) {
      el.classList.toggle('ant-menu-item-selected', h === el.getAttribute('data-gw-ph'));
    });
  }
  function _show(plugin) {
    _syncLeft(); _ov.style.display = 'block'; _updNav();
    if (plugin.iframe_src) {
      _ov.innerHTML = '<iframe src="' + _E(plugin.iframe_src)
        + '" style="position:absolute;top:0;left:0;width:100%;height:100%;border:none;"></iframe>';
    } else if (plugin.api_src) {
      _ov.innerHTML = '<div style="max-width:1100px;padding:24px 40px 48px 24px;">'
        + '<h2 style="font-size:20px;font-weight:600;margin-bottom:16px;">' + _E(plugin.label) + '</h2>'
        + '<div id="gw-plugin-body"><span class="gw-spin"></span></div></div>';
      _fetchTable(plugin.api_src, document.getElementById('gw-plugin-body'));
    } else if (plugin.html) {
      _ov.innerHTML = '<div style="padding:24px;">' + plugin.html + '</div>';
    } else {
      _ov.innerHTML = '<div style="padding:24px;color:#888;">No content configured.</div>';
    }
  }
  function _hide() { _ov.style.display = 'none'; _updNav(); }
  function _onHash() {
    var p = _plug4hash(window.location.hash);
    if (p) _show(p); else _hide();
  }
  window.addEventListener('hashchange', _onHash);
  _onHash();
  /* Sidebar nav injection */
  var _navBlock = null;
  function _injectNav() {
    var sider = document.querySelector('.ant-layout-sider-children');
    if (!sider) return;
    if (_navBlock && sider.contains(_navBlock)) { _updNav(); return; }
    var old = document.getElementById('gw-nav-plugins');
    if (old) old.remove();
    _navBlock = document.createElement('div');
    _navBlock.id = 'gw-nav-plugins';
    _navBlock.style.cssText = 'border-top:1px solid rgba(0,0,0,.06);margin-top:4px;padding-top:4px;';
    PLUGINS.forEach(function(plugin) {
      var li = document.createElement('div');
      li.className = 'ant-menu-item';
      li.setAttribute('data-gw-ph', plugin.hash);
      li.setAttribute('role', 'menuitem');
      li.style.cssText = 'padding-left:24px;display:flex;align-items:center;'
        + 'gap:10px;height:40px;line-height:40px;cursor:pointer;overflow:hidden;white-space:nowrap;';
      li.innerHTML = '<span class="anticon" style="font-size:14px;flex-shrink:0;line-height:1;">' + plugin.icon + '</span>'
        + '<span style="overflow:hidden;text-overflow:ellipsis;flex:1;min-width:0;">' + _E(plugin.label) + '</span>';
      li.addEventListener('click', function(e) {
        e.stopPropagation(); window.location.hash = plugin.hash;
      });
      _navBlock.appendChild(li);
    });
    sider.appendChild(_navBlock);
    _updNav();
  }
  var _obs = new MutationObserver(function(muts) {
    var ok = muts.some(function(m) {
      return m.target !== _navBlock && !(_navBlock && _navBlock.contains(m.target));
    });
    if (ok) setTimeout(_injectNav, 50);
  });
  _obs.observe(document.body, {childList: true, subtree: true});
  function _waitInject() {
    if (document.querySelector('.ant-layout-sider-children')) _injectNav();
    else setTimeout(_waitInject, 200);
  }
  _waitInject();
  new MutationObserver(function() { if (_ov.style.display !== 'none') _syncLeft(); })
    .observe(document.body, {attributes: true, attributeFilter: ['class'], subtree: true});
  /* Fetch + table renderer for api_src plugins */
  function _fetchTable(url, container) {
    fetch(url, {credentials: 'include'})
      .then(function(r) {
        return r.ok ? r.json() : r.json().then(function(e) {
          throw new Error(e.error || r.status);
        });
      })
      .then(function(d) { _buildTable(container, d); })
      .catch(function(e) {
        container.innerHTML = '<p style="color:#f5222d;padding:16px 0;">Error: '
          + _E(String(e)) + '</p>';
      });
  }
  function _buildTable(container, data) {
    var rows = data.rows || [];
    var meta = '<div style="display:flex;flex-wrap:wrap;align-items:center;gap:16px;margin-bottom:14px;'
      + 'padding:12px 16px;background:#fff;border-radius:4px;border:1px solid #f0f0f0;">'
      + '<span>👤 <strong>' + _E(data.user || '') + '</strong></span>'
      + '<span style="color:#bbb;">|</span>'
      + '<span>Role: <strong>' + _E(data.role_type || '') + '</strong></span>'
      + '<span style="color:#bbb;">|</span>'
      + '<span>CS Account: <strong>' + _E(data.cs_account || '\u2014') + '</strong></span></div>';
    var sid = 'gws' + Math.random().toString(36).slice(2);
    var tid = 'gwt' + Math.random().toString(36).slice(2);
    var html = meta
      + '<div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;">'
      + '<input id="' + sid + '" type="text" placeholder="🔍 Search\u2026" '
      + 'style="width:300px;height:32px;padding:0 10px;border:1px solid #d9d9d9;'
      + 'border-radius:4px;font-size:14px;">'
      + '<span style="color:#888;font-size:13px;">' + rows.length + ' entries</span></div>'
      + '<div style="overflow-x:auto;border:1px solid #f0f0f0;border-radius:4px;background:#fff;">'
      + '<table id="' + tid + '" style="width:100%;border-collapse:collapse;font-size:14px;">'
      + '<thead><tr style="background:#fafafa;">'
      + ['Type', 'Domain', 'Level', 'Project / Key'].map(function(c) {
          return '<th style="text-align:left;padding:10px 14px;border-bottom:1px solid #e8e8e8;'
            + 'font-weight:600;white-space:nowrap;">' + c + '</th>';
        }).join('') + '</tr></thead><tbody>';
    var lc = {ADMIN: '#cf1322', OPERATIONS: '#d46b08', READONLY: '#096dd9', USER: '#389e0d'};
    rows.forEach(function(row, i) {
      var clr = lc[row.level] || '#555';
      html += '<tr class="gwtr" style="background:' + (i % 2 ? '#fafafa' : '#fff') + ';">';
      html += '<td style="padding:8px 14px;border-bottom:1px solid #f0f0f0;">' + _E(row.type) + '</td>';
      html += '<td style="padding:8px 14px;border-bottom:1px solid #f0f0f0;font-family:monospace;">'
        + _E(row.domain) + '</td>';
      html += '<td style="padding:8px 14px;border-bottom:1px solid #f0f0f0;">'
        + '<span style="color:' + clr + ';font-weight:600;">' + _E(row.level) + '</span></td>';
      html += '<td style="padding:8px 14px;border-bottom:1px solid #f0f0f0;font-family:monospace;">'
        + _E(row.project || '\u2014') + '</td></tr>';
    });
    html += '</tbody></table></div>';
    container.innerHTML = html;
    var inp = document.getElementById(sid);
    var tbl = document.getElementById(tid);
    if (inp && tbl) {
      inp.addEventListener('input', function() {
        var q = inp.value.toLowerCase();
        tbl.querySelectorAll('.gwtr').forEach(function(tr) {
          tr.style.display = tr.textContent.toLowerCase().indexOf(q) >= 0 ? '' : 'none';
        });
      });
    }
    if (data.groups && data.groups.length) {
      container.insertAdjacentHTML('beforeend',
        '<h3 style="font-size:15px;font-weight:600;margin:20px 0 10px;">'
          + 'Active CS_* Groups (' + data.groups.length + ')</h3>'
          + '<div style="display:flex;flex-wrap:wrap;gap:6px;">'
          + data.groups.map(function(g) {
              return '<span style="background:#f0f5ff;border:1px solid #adc6ff;color:#2f54eb;'
                + 'padding:2px 10px;border-radius:12px;font-family:monospace;font-size:12px;">'
                + _E(g) + '</span>';
            }).join('') + '</div>');
    }
  }
})();
</script>"""

# Map of named icon identifiers → Ant Design-style inline SVG (monochrome, currentColor).
# Plugins specify icon names in config.yaml; this map resolves them to SVG strings that
# are safe to inject as innerHTML (controls the icon span in the sidebar nav item).
_ICON_SVG_MAP: dict[str, str] = {
    "table": (
        '<svg viewBox="64 64 896 896" width="1em" height="1em"'
        ' fill="currentColor" aria-hidden="true">'
        '<path d="M428 480H152c-4.4 0-8 3.6-8 8v56c0 4.4 3.6 8 8 8h276c4.4 0 8-3.6'
        ' 8-8v-56c0-4.4-3.6-8-8-8zm0-192H152c-4.4 0-8 3.6-8 8v56c0 4.4 3.6 8 8'
        ' 8h276c4.4 0 8-3.6 8-8v-56c0-4.4-3.6-8-8-8zm308 0H560c-4.4 0-8 3.6-8 8v56'
        'c0 4.4 3.6 8 8 8h176c4.4 0 8-3.6 8-8v-56c0-4.4-3.6-8-8-8zm0 192H560c-4.4'
        ' 0-8 3.6-8 8v56c0 4.4 3.6 8 8 8h176c4.4 0 8-3.6 8-8v-56c0-4.4-3.6-8-8-8z'
        'M832 64H192c-17.7 0-32 14.3-32 32v832c0 17.7 14.3 32 32 32h640c17.7 0 32-14.3'
        ' 32-32V96c0-17.7-14.3-32-32-32zm-40 824H232V688h560v200zm0-264H232V424h560v200'
        'zm0-264H232V136h560v200z"/></svg>'
    ),
}


def _inject_footer(html_bytes: bytes, identity: "OidcIdentity", provisioned: "ProvisionedUser | None" = None, ui_config: "UiConfig | None" = None) -> bytes:
    """Inject a fixed-position identity footer bar before </body>.

    Shows email, domain, account type, and active project so users always
    know which OIDC identity and context the gateway is using.
    """
    import html as _html

    email = _html.escape(identity.email or identity.sub)

    # Derive domain and account-type labels from parsed group memberships.
    # Use level.name (e.g. "ADMIN") not level.value (integer).
    parsed = parse_groups(identity.groups)
    _LEVEL_LABEL = {
        PermLevel.ADMIN:      "Admin",
        PermLevel.OPERATIONS: "Ops",
        PermLevel.READONLY:   "Read-only",
    }
    domain_labels: list[str] = []
    for da in parsed.domain_access:
        domain_labels.append(f"{da.domain} ({_LEVEL_LABEL.get(da.level, da.level.name)})")
    domain_str = _html.escape(", ".join(domain_labels) or "ROOT")

    # Account type: highest privilege across all domains
    if any(da.level == PermLevel.ADMIN for da in parsed.domain_access):
        acct_type = "Admin"
    elif any(da.level == PermLevel.OPERATIONS for da in parsed.domain_access):
        acct_type = "Ops"
    elif any(da.level == PermLevel.READONLY for da in parsed.domain_access):
        acct_type = "Read-only"
    else:
        acct_type = "User"

    # Footer background color: root admin → red, domain admin → orange, else → blue
    if parsed.is_root_admin:
        bg_color = "rgba(175,20,20,0.95)"
    elif any(da.level == PermLevel.ADMIN for da in parsed.domain_access):
        bg_color = "rgba(185,90,0,0.95)"
    elif any(da.level == PermLevel.OPERATIONS for da in parsed.domain_access):
        bg_color = "rgba(140,80,0,0.95)"
    else:
        bg_color = "rgba(14,90,190,0.93)"

    footer = f"""
<div id="oidcgw-bar">

  <!-- Sidebar toggle: programmatic .click() still fires Vue @click even with pointer-events:none on parent -->
  <button id="gw-toggle" title="Toggle sidebar">&#9776;</button>

  <!-- Logo -->
  <span id="gw-logo">&#9729; CloudStack</span>

  <!-- Project selector (hidden until Vue ready or if user has no project access) -->
  <div id="gw-proj-wrap">
    <select id="gw-proj-sel"><option value="0">Default View</option></select>
  </div>

  <div style="flex:1"></div>

  <!-- Create dropdown (shown only when create-able APIs exist) -->
  <div id="gw-create-wrap" class="gw-aw" style="display:none">
    <button id="gw-create-btn" class="gw-create-btn">&#43; Create &#9662;</button>
    <div id="gw-create-drop" class="gw-drop"></div>
  </div>

  <!-- Notification bell -->
  <div id="gw-notify-wrap" class="gw-aw" title="Notifications">
    <span style="font-size:18px;line-height:1">&#128276;</span>
    <span id="gw-notify-badge" class="gw-badge" style="display:none">0</span>
  </div>

  <!-- Role badge (server-rendered; always visible) -->
  <span id="gw-role-badge" title="OIDCGW: {domain_str}">{acct_type}</span>

  <!-- User dropdown -->
  <div id="gw-user-wrap" class="gw-aw">
    <div id="gw-user-btn" style="display:flex;align-items:center;gap:6px;padding:4px 8px;border-radius:4px">
      <div id="gw-avatar" class="gw-avatar">?</div>
      <span id="gw-username">{email}</span>
      <span style="font-size:10px;opacity:.45">&#9662;</span>
    </div>
    <div id="gw-user-drop" class="gw-drop gw-drop-r">
      <div class="gw-di" id="gw-mi-profile">&#128100;&nbsp;Profile</div>
      <div class="gw-di" id="gw-mi-limits">&#9881;&nbsp;Limits</div>
      <div class="gw-dsep"></div>
      <div class="gw-di" id="gw-mi-signout">&#10132;&nbsp;Sign&nbsp;out</div>
    </div>
  </div>

</div>
<style>
/* ── OIDCGW replacement header bar ─────────────────────────────────
 * height: 64px — matches .ant-layout-header exactly.
 * The native header is hidden via opacity:0 below; its <a-affix>
 * placeholder div (a separate sibling element) is NOT affected and
 * keeps its 64px height, so .layout-content.is-header-fixed
 * {{ margin-top:78px }} and all sidebar spacing stay correct.
 * No body padding-top is needed — the native layout already provides
 * the spacing via the affix placeholder + content margin.
 * ────────────────────────────────────────────────────────────────── */
html {{ scroll-padding-top: 64px; }}
#oidcgw-bar {{
  position: fixed; top: 0; left: 0; right: 0; z-index: 99999;
  height: 64px;
  background: #fff;
  box-shadow: 0 1px 4px rgba(0,21,41,.08);
  display: flex; align-items: center;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  font-size: 14px; color: rgba(0,0,0,.65);
}}
/* Hide native header — visibility:hidden keeps layout dimensions (affix
 * placeholder still provides 64 px spacing) but makes ALL child content
 * invisible, including overflow/positioned children like the trigger icon. */
.ant-layout-header,
.ant-header-fixedHeader {{
  visibility: hidden !important;
  opacity: 0 !important;
  pointer-events: none !important;
}}
/* Hide maintenance/shutdown banners — if visible they push the header
 * down by 25 px which would poke below our fixed bar. */
.maintenanceHeader,
.shutdownHeader,
.button-clear-notification {{
  visibility: hidden !important;
  pointer-events: none !important;
}}
/* Sidebar toggle */
#gw-toggle {{
  background: none; border: none; outline: none; cursor: pointer;
  padding: 0 24px; height: 64px; font-size: 20px; color: inherit;
  display: flex; align-items: center; flex-shrink: 0; transition: color .3s;
}}
#gw-toggle:hover {{ color: #1890ff; }}
/* Logo */
#gw-logo {{
  font-size: 17px; font-weight: 600; color: #1890ff;
  flex-shrink: 0; padding-right: 20px; white-space: nowrap; cursor: default;
}}
/* Project selector */
#gw-proj-wrap {{ flex: 0 0 auto; min-width: 160px; max-width: 27vw; padding: 0 8px; }}
#gw-proj-sel {{
  width: 100%; height: 32px; padding: 0 8px;
  border: 1px solid #d9d9d9; border-radius: 4px;
  background: #fff; font-size: 14px; color: rgba(0,0,0,.65);
  cursor: pointer; outline: none; transition: border-color .3s;
}}
#gw-proj-sel:focus {{ border-color: #40a9ff; }}
/* Generic action wrapper */
.gw-aw {{
  position: relative; height: 64px;
  display: flex; align-items: center;
  padding: 0 10px; cursor: pointer; transition: background .3s;
}}
.gw-aw:hover {{ background: rgba(0,0,0,.025); }}
/* Role badge */
#gw-role-badge {{
  flex-shrink: 0; margin: 0 6px;
  padding: 2px 10px; border-radius: 12px;
  font-size: 11px; font-weight: 600; color: #fff;
  background: {bg_color}; white-space: nowrap; cursor: default;
}}
/* Create button */
.gw-create-btn {{
  background: #1890ff; color: #fff; border: none; border-radius: 4px;
  padding: 0 15px; height: 32px; cursor: pointer; font-size: 14px;
  display: flex; align-items: center; gap: 4px; white-space: nowrap;
  transition: background .3s;
}}
.gw-create-btn:hover {{ background: #40a9ff; }}
/* Notification badge */
.gw-badge {{
  position: absolute; top: 10px; right: 2px;
  background: #f5222d; color: #fff; border-radius: 10px;
  font-size: 10px; min-width: 16px; height: 16px; line-height: 16px;
  text-align: center; padding: 0 4px; pointer-events: none;
}}
/* Avatar */
.gw-avatar {{
  width: 28px; height: 28px; border-radius: 50%;
  background: #1890ff; color: #fff; font-size: 12px; font-weight: 600;
  display: flex; align-items: center; justify-content: center;
  flex-shrink: 0; overflow: hidden;
}}
.gw-avatar img {{ width: 100%; height: 100%; object-fit: cover; }}
/* Dropdowns — styled to match Ant Design dropdown menus */
.gw-drop {{
  display: none; position: absolute; top: 58px; left: 0; z-index: 100001;
  background: #fff; border-radius: 2px;
  box-shadow: 0 3px 6px -4px rgba(0,0,0,.12),
              0 6px 16px 0 rgba(0,0,0,.08),
              0 9px 28px 8px rgba(0,0,0,.05);
  min-width: 160px; padding: 4px 0;
}}
.gw-drop.gw-open {{ display: block; }}
.gw-drop-r {{ left: auto; right: 0; }}
.gw-di {{
  padding: 5px 12px; cursor: pointer; color: rgba(0,0,0,.85);
  white-space: nowrap; transition: background .15s;
  display: flex; align-items: center; gap: 8px;
  font-size: 14px; line-height: 22px;
}}
.gw-di:hover {{ background: rgba(0,0,0,.018); }}
.gw-dsep {{ height: 1px; background: rgba(0,0,0,.06); margin: 4px 0; }}
/* Dark mode (class toggled by JS — triggered by navTheme=dark OR user darkMode) */
#oidcgw-bar.gw-dark {{
  background: #001529; color: rgba(255,255,255,.85);
  box-shadow: 0 1px 4px rgba(0,0,0,.3);
}}
#oidcgw-bar.gw-dark #gw-toggle {{ color: rgba(255,255,255,.65); }}
#oidcgw-bar.gw-dark #gw-toggle:hover {{ color: #fff; }}
#oidcgw-bar.gw-dark .gw-aw:hover {{ background: rgba(255,255,255,.08); }}
#oidcgw-bar.gw-dark #gw-proj-sel {{
  background: #001529; color: rgba(255,255,255,.85); border-color: #434343;
}}
#oidcgw-bar.gw-dark .gw-drop {{
  background: #1d1d1d; border: 1px solid #434343;
  box-shadow: 0 3px 6px -4px rgba(0,0,0,.48),
              0 6px 16px 0 rgba(0,0,0,.32),
              0 9px 28px 8px rgba(0,0,0,.2);
}}
#oidcgw-bar.gw-dark .gw-di {{ color: rgba(255,255,255,.85); }}
#oidcgw-bar.gw-dark .gw-di:hover {{ background: rgba(255,255,255,.08); }}
#oidcgw-bar.gw-dark .gw-dsep {{ background: rgba(255,255,255,.12); }}
</style>
<script>
/* ── 1. Bar init — Vue store + router integration ──────────────────
 * Waits for __vue_app__ on #app (stable Vue 3 DevTools API), then
 * wires every interactive element to Vuex store + Vue Router.
 * ─────────────────────────────────────────────────────────────────── */
(function() {{
  /* HTML-escape helper for dynamic content inserted into innerHTML */
  function _E(s) {{
    return String(s == null ? '' : s)
      .replace(/&/g,'&amp;').replace(/</g,'&lt;')
      .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }}
  function _gwCk(name) {{
    var m = document.cookie.match('(?:^|;\\s*)' + name + '=([^;]*)');
    return m ? decodeURIComponent(m[1]) : null;
  }}
  /* Dropdown helpers */
  function _closeDrops() {{
    document.querySelectorAll('.gw-drop.gw-open').forEach(function(d) {{
      d.classList.remove('gw-open');
    }});
  }}
  document.addEventListener('click', _closeDrops);

  /* Wait for Vue to mount */
  var _store, _router, _inited = false, _retries = 0;
  function _tryInit() {{
    if (_retries++ > 200) return;          /* give up after 20 s */
    var app = document.getElementById('app');
    if (!app || !app.__vue_app__) {{ setTimeout(_tryInit, 100); return; }}
    var vp = app.__vue_app__.config.globalProperties;
    _store = vp.$store; _router = vp.$router;
    if (!_store || !_router) {{ setTimeout(_tryInit, 100); return; }}
    /* Wait until APIs are loaded — routes are registered as part of the
       same async flow (GenerateRoutes → addRoute), so by the time apis
       exist in the store the dynamic routes are also ready. */
    if (!Object.keys(_store.getters.apis || {{}}).length) {{
      setTimeout(_tryInit, 100); return;
    }}
    if (_inited) return; _inited = true;
    _initToggle(); _initProject(); _initUser();
    _initCreate(); _initNotify(); _initTheme();
  }}
  setTimeout(_tryInit, 100);

  /* ── Navigation helper ───────────────────────────────────────────
   * Use window.location.hash directly — always reliable in hash-mode
   * SPAs.  Vue Router's hashchange listener picks it up and navigates.
   * router.push() is intentionally avoided here: in Vue Router 4 it
   * RESOLVES (not rejects) on NavigationFailure, so .catch() never
   * fires, making silent 404s impossible to handle from outside.
   * ─────────────────────────────────────────────────────────────────── */
  function _gwNav(path, query) {{
    var qs = '';
    if (query) {{
      qs = '?' + Object.keys(query).map(function(k) {{
        return encodeURIComponent(k) + '=' + encodeURIComponent(query[k]);
      }}).join('&');
    }}
    window.location.hash = '#' + path + qs;
  }}

  /* 1a. Sidebar toggle */
  function _initToggle() {{
    document.getElementById('gw-toggle').addEventListener('click', function(e) {{
      e.stopPropagation();
      /* .trigger is inside the opacity:0 native header; programmatic
         .click() fires Vue @click even with pointer-events:none on parent */
      var t = document.querySelector('.trigger');
      if (t) t.click();
    }});
  }}

  /* 1b. Project selector */
  function _initProject() {{
    var sel  = document.getElementById('gw-proj-sel');
    var wrap = document.getElementById('gw-proj-wrap');
    if (!sel) return;
    if (!('listProjects' in (_store.getters.apis || {{}}))) {{
      wrap.style.display = 'none'; return;
    }}
    var _projects = [];
    /* Keep <select> in sync when other SPA code changes the project */
    _store.watch(function(s, g) {{ return g.project && g.project.id; }},
      function(id) {{ sel.value = id || '0'; }});
    function _populateSel(list) {{
      _projects = list || [];
      var cur  = _store.getters.project;
      var html = '<option value="0">Default View</option>';
      _projects.forEach(function(p) {{
        var n = _E(p.displaytext || p.name || p.id);
        var s = (cur && cur.id === p.id) ? ' selected' : '';
        html += '<option value="' + _E(p.id) + '"' + s + '>' + n + '</option>';
      }});
      sel.innerHTML = html;
      if (cur && cur.id) sel.value = cur.id;
    }}
    /* Direct fetch with sessionkey — CS session auth requires BOTH the
       JSESSIONID cookie AND the sessionkey parameter.  Without sessionkey
       CS returns 401 and Tomcat can reissue a new JSESSIONID cookie that
       overwrites the browser's real session, causing every subsequent SPA
       axios request to fail with 401 and trigger the logout loop.         */
    var _sk = null;
    try {{
      var _skRaw = localStorage.getItem('primate__Access-Token');
      if (_skRaw) _sk = JSON.parse(_skRaw);
    }} catch(e) {{}}
    if (!_sk) {{
      console.warn('[GW] listProjects: no Access-Token in localStorage, skipping');
      return;
    }}
    fetch('/client/api/?command=listProjects&response=json' +
          '&details=min&listall=true&pagesize=300' +
          '&sessionkey=' + encodeURIComponent(_sk),
          {{ credentials:'include' }})
      .then(function(r) {{ return r.ok ? r.json() : r.json(); }})
      .then(function(data) {{
        if (!data) {{ console.warn('[GW] listProjects: no response'); return; }}
        if (data.errorresponse) {{
          console.warn('[GW] listProjects CS error:', data.errorresponse.errortext);
          return;
        }}
        _populateSel((data.listprojectsresponse || {{}}).project || []);
      }})
      .catch(function(e) {{ console.error('[GW] listProjects fetch error:', e); }});
    sel.addEventListener('change', function(e) {{
      e.stopPropagation();
      var id   = sel.value;
      var proj = null;
      for (var i = 0; i < _projects.length; i++) {{
        if (_projects[i].id === id) {{ proj = _projects[i]; break; }}
      }}
      /* Match native ProjectMenu.changeProject() dispatch order */
      _store.dispatch('ProjectView', id === '0' ? 0 : id);
      _store.dispatch('SetProject',  proj || {{}});
      _store.dispatch('ToggleTheme', (id && id !== '0') ? 'dark' : 'light');
      if (_router.currentRoute.value.name !== 'dashboard') {{
        _gwNav('/dashboard');
      }}
    }});
  }}

  /* 1c. User info + dropdown */
  function _initUser() {{
    var info     = _store.getters.userInfo || {{}};
    var avatarEl = document.getElementById('gw-avatar');
    var nameEl   = document.getElementById('gw-username');
    var initials = ((info.firstname || '').charAt(0) +
                   (info.lastname  || '').charAt(0)).toUpperCase() || '?';
    if (avatarEl) {{
      var av = _store.getters.avatar;
      if (av) avatarEl.innerHTML = '<img src="' + _E(av) + '" alt="">';
      else    avatarEl.textContent = initials;
    }}
    if (nameEl) {{
      var name = [info.firstname, info.lastname].filter(Boolean).join(' ')
                 || info.username || '';
      if (name) nameEl.textContent = name;
    }}
    document.getElementById('gw-user-btn').addEventListener('click', function(e) {{
      e.stopPropagation();
      var d = document.getElementById('gw-user-drop');
      var was = d.classList.contains('gw-open');
      _closeDrops(); if (!was) d.classList.add('gw-open');
    }});
    document.getElementById('gw-mi-profile').addEventListener('click', function() {{
      _closeDrops();
      /* Read userInfo at click-time — guaranteed populated by then */
      var _i = _store.getters.userInfo || {{}};
      _gwNav('/accountuser/' + _i.id);
    }});
    document.getElementById('gw-mi-limits').addEventListener('click', function() {{
      _closeDrops();
      var _i = _store.getters.userInfo || {{}};
      _gwNav('/account/' + _i.accountid, {{ tab: 'limits' }});
    }});
    document.getElementById('gw-mi-signout').addEventListener('click', function() {{
      _closeDrops(); window.location.href = '/auth/logout';
    }});
  }}

  /* 1d. Create menu */
  function _initCreate() {{
    var apis  = _store.getters.apis || {{}};
    var items = [
      {{ api:'deployVirtualMachine',    label:'Instance',      path:'/action/deployVirtualMachine' }},
      {{ api:'createKubernetesCluster', label:'Kubernetes',    path:'/kubernetes',    q:{{action:'createKubernetesCluster'}} }},
      {{ api:'createVolume',            label:'Volume',        path:'/volume',        q:{{action:'createVolume'}} }},
      {{ api:'createNetwork',           label:'Network',       path:'/guestnetwork',  q:{{action:'createNetwork'}} }},
      {{ api:'createVPC',               label:'VPC',           path:'/vpc',           q:{{action:'createVPC'}} }},
      {{ api:'registerTemplate',        label:'Template',      path:'/template',      q:{{action:'registerTemplate'}} }},
      {{ api:'deployVnfAppliance',      label:'VNF Appliance', path:'/action/deployVnfAppliance' }},
    ];
    var avail = items.filter(function(i) {{ return i.api in apis; }});
    if (!avail.length) return;
    var wrap = document.getElementById('gw-create-wrap');
    var drop = document.getElementById('gw-create-drop');
    wrap.style.display = '';
    drop.innerHTML = avail.map(function(item, idx) {{
      return '<div class="gw-di" data-idx="' + idx + '">' + _E(item.label) + '</div>';
    }}).join('');
    drop._avail = avail;
    document.getElementById('gw-create-btn').addEventListener('click', function(e) {{
      e.stopPropagation();
      var was = drop.classList.contains('gw-open');
      _closeDrops(); if (!was) drop.classList.add('gw-open');
    }});
    drop.addEventListener('click', function(e) {{
      var el = e.target.closest('[data-idx]');
      if (!el) return;
      var item = drop._avail[parseInt(el.dataset.idx, 10)];
      if (!item) return;
      _closeDrops();
      _gwNav(item.path, item.q || null);
    }});
  }}

  /* 1e. Notification count */
  function _initNotify() {{
    var badge = document.getElementById('gw-notify-badge');
    var wrap  = document.getElementById('gw-notify-wrap');
    function _upd(n) {{
      badge.textContent = n > 99 ? '99+' : String(n);
      badge.style.display = n > 0 ? '' : 'none';
    }}
    _upd(_store.getters.countNotify || 0);
    _store.watch(function(s, g) {{ return g.countNotify; }},
      function(n) {{ _upd(n || 0); }});
    /* Delegate click to the hidden real HeaderNotice button */
    wrap.addEventListener('click', function(e) {{
      e.stopPropagation();
      var bell = document.querySelector('.header-notice-opener');
      if (bell) bell.click();
    }});
  }}

  /* 1f. Dark mode sync — watch navTheme (state.app.theme) AND the global
   *     darkMode (state.user.darkMode) so the bar stays in sync with both
   *     the native header colour and the full-page dark-mode toggle.     */
  function _initTheme() {{
    var bar = document.getElementById('oidcgw-bar');
    function _apply() {{
      var dark = (_store.state.app.theme === 'dark') ||
                 !!_store.state.user.darkMode;
      bar.classList.toggle('gw-dark', dark);
      var sel = document.getElementById('gw-proj-sel');
      if (sel) {{
        sel.style.background  = dark ? '#001529' : '#fff';
        sel.style.color       = dark ? 'rgba(255,255,255,.85)' : 'rgba(0,0,0,.65)';
        sel.style.borderColor = dark ? '#434343' : '#d9d9d9';
      }}
    }}
    _apply();
    _store.watch(function(s) {{
      return s.app.theme + ':' + s.user.darkMode;
    }}, _apply);
  }}
}})();

/* ── 2. Logout bridge ───────────────────────────────────────────────
 * PRIMARY:  /auth/me heartbeat every 2 s — 401 = session gone.
 * SECONDARY: _gw_logout_pending cookie signal (set by proxy).
 * TERTIARY:  Hash detection (#/user/login) — with 10 s grace period on
 *            initial page load so the SPA can finish booting before we
 *            treat a transient #/user/login navigation as a logout.
 * ─────────────────────────────────────────────────────────────────── */
(function() {{
  var _gwBoot = Date.now();
  function _gwCookie(name) {{
    var m = document.cookie.match('(?:^|;\\s*)' + name + '=([^;]*)');
    return m ? m[1] : null;
  }}
  function _gwIsLoginHash(h) {{
    return h === '#/user/login' || h.startsWith('#/user/login?') ||
           h === '#/user/login/';
  }}
  /* ── Hash tracking ─────────────────────────────────────────────────
   * Save the current SPA hash to a short-lived cookie so the bridge page
   * can restore it after a login redirect.  A cookie (not sessionStorage)
   * is used because Firefox clears sessionStorage on cross-origin navigation
   * (i.e. when the tab leaves localhost for the IdP and comes back).
   * We skip #/user/login (the SPA's own login screen) and bare hashes.
   * ─────────────────────────────────────────────────────────────────── */
  function _gwSaveHash(h) {{
    if (!h || h === '#' || h === '#/' || _gwIsLoginHash(h)) return;
    document.cookie = '_gw_hash=' + encodeURIComponent(h) + '; path=/; samesite=lax; max-age=600';
  }}
  // Capture the hash that was present when this page first loaded (covers
  // the "user pastes a deep-link URL" case before the SPA changes the hash).
  _gwSaveHash(window.location.hash);

  var _redirecting = false;
  function _gwGoLogout() {{
    if (_redirecting) return;
    _redirecting = true;
    window.location.replace('/auth/logout');
  }}
  function _gwCheck() {{
    if (_gwCookie('_gw_logout_pending') === '1') {{ _gwGoLogout(); return; }}
    // Skip hash-based detection during the first 10 s — the SPA may push
    // #/user/login transiently while GetInfo() is still initialising.
    if (Date.now() - _gwBoot > 10000 && _gwIsLoginHash(window.location.hash)) {{ _gwGoLogout(); return; }}
  }}
  _gwCheck();
  setInterval(_gwCheck, 200);
  window.addEventListener('hashchange', function() {{
    // Track every real navigation so the post-login bridge can restore it.
    _gwSaveHash(window.location.hash);
    // Always honour hash changes after the boot period; before that, only
    // honour if _gw_logout_pending is also set (explicit proxy-side logout).
    if (Date.now() - _gwBoot > 10000) _gwCheck();
    else if (_gwCookie('_gw_logout_pending') === '1') _gwGoLogout();
  }});
  function _gwHeartbeat() {{
    if (_redirecting) return;
    fetch('/auth/me', {{ credentials: 'include', cache: 'no-store' }})
      .then(function(r) {{ if (r.status === 401) _gwGoLogout(); }})
      .catch(function() {{}});
  }}
  setTimeout(function() {{
    _gwHeartbeat();
    setInterval(_gwHeartbeat, 2000);
  }}, 1000);
}})();
</script>"""

    # Build per-role CSS selector hides + plugin system script
    import json as _jui
    extra = b""
    if ui_config is not None:
        role_type = _get_role_type(parsed)
        selectors = list(dict.fromkeys(
            ui_config.hide_selectors.get("*", []) +
            ui_config.hide_selectors.get(role_type, [])
        ))
        if selectors:
            rules = "\n".join(
                f"{sel} {{ display: none !important; }}" for sel in selectors
            )
            extra += f'<style id="gw-hide">{rules}</style>\n'.encode()
        visible_plugins = [
            p for p in ui_config.plugins
            if not p.roles or role_type in p.roles
        ]
        if visible_plugins:
            _plugin_data = [
                {
                    "id": p.id,
                    "label": p.label,
                    "icon": _ICON_SVG_MAP.get(p.icon, p.icon),
                    "hash": p.hash or f"#/gw-{p.id}",
                    "iframe_src": p.iframe_src,
                    "html": p.html,
                    "api_src": p.api_src,
                }
                for p in visible_plugins
            ]
            extra += _PLUGIN_JS_TMPL.replace(
                "/*PLUGINS_JSON*/", _jui.dumps(_plugin_data)
            ).encode()

    tag = b"</body>"
    idx = html_bytes.lower().rfind(tag)
    if idx == -1:
        return html_bytes + footer.encode() + extra
    return html_bytes[:idx] + footer.encode() + extra + html_bytes[idx:]


def build_app(
    config: AppConfig,
    cs_client: CloudStackClient,
    cache: BaseCache,
    oidc_provider: OidcProvider | None = None,
) -> FastAPI:
    """Construct and return the FastAPI application."""

    provisioner = Provisioner(cs_client, config)
    reconciler = Reconciler(cs_client, cache, config)
    oidc_cfg = config.oidc  # convenience alias; may be None in header-fallback mode

    @asynccontextmanager
    async def _lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
        await cs_client._ensure_client()  # pre-warm the HTTP client
        reconciler.start()
        logger.info("Middleware started — upstream: %s", config.server.upstream_url)
        yield
        reconciler.stop()
        await cs_client.close()
        await cache.close()
        logger.info("Middleware shut down")

    app = FastAPI(
        title="OIDC-CloudStack Middleware",
        description="All-in-one OIDC authentication + CloudStack auto-provisioning proxy",
        version="1.0.0",
        lifespan=_lifespan,
    )

    # ------------------------------------------------------------------
    # Health endpoints
    # ------------------------------------------------------------------

    @app.get("/healthz", tags=["ops"])
    async def healthz() -> dict:
        return {"status": "ok"}

    @app.get("/readyz", tags=["ops"])
    async def readyz() -> JSONResponse:
        cs_ok = await cs_client.probe()
        oidc_ok = (await oidc_provider.probe()) if oidc_provider else True
        if cs_ok and oidc_ok:
            return JSONResponse({"status": "ready"})
        reasons = []
        if not cs_ok:
            reasons.append("CloudStack unreachable")
        if not oidc_ok:
            reasons.append("OIDC provider unreachable")
        return JSONResponse(
            {"status": "unhealthy", "reason": ", ".join(reasons)},
            status_code=503,
        )

    # ------------------------------------------------------------------
    # Admin endpoints
    # ------------------------------------------------------------------

    @app.post("/admin/cache/clear", tags=["admin"])
    async def admin_cache_clear() -> dict:
        await cache.clear()
        logger.info("Cache cleared via admin endpoint")
        return {"status": "cleared"}

    @app.post("/admin/reconcile", tags=["admin"])
    async def admin_reconcile() -> dict:
        summary = await reconciler.run_once()
        return {"status": "complete", "summary": summary}

    # ------------------------------------------------------------------
    # Plugin endpoints
    # ------------------------------------------------------------------

    @app.get("/gw/plugins/access-map", tags=["plugins"])
    async def gw_plugin_access_map(request: Request) -> JSONResponse:
        """Return the authenticated user's consolidated access map.

        Combines all domain-role grants and project memberships from their
        OIDC group list into a single searchable JSON structure.  Used by
        the built-in 'Access Map' SPA plugin (ui.plugins[].api_src).
        """
        identity = _get_identity(request, oidc_cfg, oidc_provider)
        if identity is None:
            return JSONResponse({"error": "Not authenticated"}, status_code=401)

        _parsed = parse_groups(identity.groups)
        cache_key = identity.cache_key()
        _cached = await cache.get(cache_key)
        _provisioned = _cached.provisioned if _cached else None

        _LEVEL_NAME = {
            PermLevel.ADMIN:      "ADMIN",
            PermLevel.OPERATIONS: "OPERATIONS",
            PermLevel.READONLY:   "READONLY",
        }
        rows: list[dict] = []

        # Domain-role rows (highest privilege first per domain)
        for da in sorted(_parsed.domain_access, key=lambda x: (x.domain, -x.level)):
            rows.append({
                "type": "Domain Role",
                "domain": da.domain,
                "level": _LEVEL_NAME.get(da.level, da.level.name),
                "project": "",
            })

        # Project-access rows
        for pa in sorted(_parsed.project_access, key=lambda x: (x.domain, x.project)):
            rows.append({
                "type": "Project",
                "domain": pa.domain,
                "level": "USER",
                "project": pa.project,
            })

        return JSONResponse({
            "user": identity.email or identity.sub,
            "preferred_username": identity.preferred_username,
            "role_type": _get_role_type(_parsed),
            "groups": sorted(g for g in identity.groups if g.startswith("CS_")),
            "cs_account": _provisioned.account_name if _provisioned else "",
            "rows": rows,
        })

    # ------------------------------------------------------------------
    # OIDC auth routes
    # ------------------------------------------------------------------

    @app.get("/auth/callback", tags=["auth"])
    async def auth_callback(request: Request) -> Response:
        """Handle the IdP redirect back with ?code=&state="""
        if oidc_provider is None or oidc_cfg is None:
            return JSONResponse({"error": "OIDC not configured"}, status_code=501)

        error = request.query_params.get("error")
        if error:
            desc = request.query_params.get("error_description", error)
            logger.warning("OIDC error from IdP: %s — %s", error, desc)
            return JSONResponse({"error": "OIDC error", "detail": desc}, status_code=401)

        code = request.query_params.get("code", "")
        state = request.query_params.get("state", "")
        if not code or not state:
            return JSONResponse({"error": "Missing code or state parameter"}, status_code=400)

        try:
            identity, original_path = await oidc_provider.handle_callback(code, state)
        except OidcAuthError as exc:
            logger.warning("OIDC callback failed: %s — restarting OIDC flow", exc)
            # State expired or missing (e.g. server restarted between the
            # authorization redirect and the IdP callback).  Auto-restart the
            # login flow so the user never sees a raw JSON error.
            new_auth_url = await oidc_provider.authorization_redirect_url(
                original_path="/client/"
            )
            return RedirectResponse(url=new_auth_url, status_code=302)

        # Gate users with no CS_* groups before provisioning or touching the CS UI.
        # Set the session cookie so /auth/denied can display their identity.
        parsed_groups = parse_groups(identity.groups)
        if not parsed_groups.has_any_access:
            logger.warning(
                "Login denied for %s (%s): no CS_* groups assigned (groups=%r)",
                identity.sub, identity.email, identity.groups,
            )
            cookie_value = oidc_provider.create_session_cookie(identity)
            response = RedirectResponse(url="/auth/denied", status_code=302)
            response.set_cookie(
                key=oidc_cfg.session_cookie_name,
                value=cookie_value,
                max_age=oidc_cfg.session_ttl,
                httponly=True,
                samesite="lax",
                secure=oidc_cfg.issuer_url.startswith("https"),
            )
            return response

        # Provision immediately so the first real request is fast, and always
        # resolve the provisioned user data (needed for CS session creation below).
        cache_key = identity.cache_key()
        cached = await cache.get(cache_key)
        if cached is not None:
            provisioned = cached.provisioned
        else:
            logger.info("Provisioning CloudStack objects for %s", identity.sub)
            try:
                provisioned = await provisioner.provision(identity)
                await cache.set(
                    cache_key,
                    CacheEntry(
                        identity=identity,
                        provisioned=provisioned,
                        groups_hash=identity.groups_hash(),
                    ),
                )
            except CloudStackError as exc:
                logger.error("Provisioning failed for %s: %s", identity.sub, exc)
                return JSONResponse(
                    {"error": "Provisioning failed", "detail": str(exc)}, status_code=502
                )
            except Exception as exc:
                logger.exception("Unexpected provisioning error for %s", identity.sub)
                return JSONResponse(
                    {"error": "Provisioning error", "detail": str(exc)}, status_code=502
                )

        # ----------------------------------------------------------------
        # Establish a CloudStack session so the Vue SPA can authenticate.
        #
        # Strategy: reset the user's password to a one-shot random token,
        # then immediately call the unauthenticated ``login`` API to create
        # a real Jetty HTTP session.  The resulting JSESSIONID / sessionkey
        # / userid cookies are forwarded to the browser so that all
        # subsequent CS API calls are authenticated normally — no proxy-side
        # signing is required.
        # ----------------------------------------------------------------
        cs_login_info: dict = {}
        cs_set_cookies: dict[str, str] = {}
        if provisioned.user_id and provisioned.user_slug:
            try:
                temp_pass = secrets.token_urlsafe(16)
                await cs_client.update_user(provisioned.user_id, password=temp_pass)
                cs_login_info, cs_set_cookies = await cs_client.login_user(
                    provisioned.user_slug,
                    temp_pass,
                    domain_id=provisioned.domain_id if provisioned.domain_id else None,
                )
                logger.info(
                    "CS session established for %s (got cookies: %s)",
                    identity.sub, list(cs_set_cookies.keys()),
                )
            except Exception as exc:
                # Non-fatal: the user lands on the login page instead of the
                # dashboard, which is acceptable.
                logger.warning(
                    "Could not establish CS session for %s: %s — "
                    "user will see a login prompt",
                    identity.sub, exc,
                )

        # Use the redirect_uri to determine whether to set Secure cookies.
        # The issuer (IdP) is always HTTPS, but the gateway itself may run over
        # plain HTTP (e.g. localhost dev).  Browsers silently drop Secure cookies
        # on HTTP origins, which would lose every session/CS cookie we set here.
        is_secure = (oidc_cfg.redirect_uri or "").startswith("https")
        cookie_value = oidc_provider.create_session_cookie(identity)
        redirect_to = original_path if (original_path and original_path.startswith("/")) else "/"

        # Serve a bridge page instead of a bare redirect.
        # The page calls listApis via fetch, populates primate__APIS in
        # localStorage (vue-web-storage format), then redirects.  This makes
        # the SPA's GetInfo() take the hasAuth=true path on the next load,
        # which is the only path that calls resolve() when the user hasn't
        # gone through the SPA's own login form.
        import json as _json
        bridge_html = _BRIDGE_PAGE.format(
            redirect_to_js=_json.dumps(redirect_to),
        )
        response = Response(content=bridge_html, media_type="text/html")

        # Reset the auth-loop counter on successful login.
        response.delete_cookie("_oidc_attempts", path="/")

        # Our OIDC gateway session cookie (HttpOnly, for server-side auth).
        response.set_cookie(
            key=oidc_cfg.session_cookie_name,
            value=cookie_value,
            max_age=oidc_cfg.session_ttl,
            httponly=True,
            samesite="lax",
            secure=is_secure,
        )

        # CS JSESSIONID — the servlet-container session cookie (HttpOnly).
        # Use path="/" so the cookie is visible to the SPA regardless of
        # whether the browser's current path is "/client" or "/".
        if "JSESSIONID" in cs_set_cookies:
            response.set_cookie(
                key="JSESSIONID",
                value=cs_set_cookies["JSESSIONID"],
                path="/",
                httponly=True,
                samesite="lax",
                secure=is_secure,
            )

        # CS sessionkey — sent as ?sessionkey=… on every API call by the SPA.
        cs_sessionkey = cs_login_info.get("sessionkey") or cs_set_cookies.get("sessionkey", "")
        if cs_sessionkey:
            response.set_cookie(
                key="sessionkey",
                value=cs_sessionkey,
                path="/",
                httponly=False,
                samesite="lax",
                secure=is_secure,
            )

        # CS userid — read by permission.js to verify the user is logged in.
        cs_userid = cs_login_info.get("userid", "")
        if cs_userid:
            response.set_cookie(
                key="userid",
                value=str(cs_userid),
                path="/",
                httponly=False,
                samesite="lax",
                secure=is_secure,
            )

        # Signal to the CloudStack SPA that we authenticated via an external
        # IdP (analogous to SAML SSO).  permission.js checks this cookie and
        # calls store.commit('SET_LOGIN_FLAG', true), which puts GetInfo() on
        # the loginFlag code-path.  That path calls listApis itself and always
        # resolves — giving us a reliable fallback when primate__APIS is not
        # yet in localStorage (e.g. the bridge-page listApis fetch races with
        # the window.location.href redirect and the callback fires too late).
        # If primate__APIS IS present (hasAuth path), GetInfo() resolves via
        # listUsers (~200 ms) and the loginFlag branch is never entered.
        response.set_cookie(
            key="isSAML",
            value="true",
            path="/",
            httponly=False,
            samesite="lax",
            secure=is_secure,
        )

        return response

    @app.get("/auth/logout", tags=["auth"])
    async def auth_logout() -> Response:
        response = RedirectResponse(url="/auth/login", status_code=302)
        if oidc_cfg is not None:
            response.delete_cookie(key=oidc_cfg.session_cookie_name)
        # Also clear CloudStack session cookies so stale values don't survive
        response.delete_cookie("JSESSIONID", path="/")
        response.delete_cookie("sessionkey", path="/")
        response.delete_cookie("userid", path="/")
        response.delete_cookie("isSAML", path="/")
        response.delete_cookie("_oidc_attempts", path="/")
        response.delete_cookie("_gw_logout_pending", path="/")
        return response

    @app.get("/auth/denied", tags=["auth"])
    async def auth_denied(request: Request) -> Response:
        """Access-denied page — shown when a user has no CS_* group assignments."""
        import html as _html
        import json as _json
        identity = _get_identity(request, oidc_cfg, oidc_provider)
        email = identity.email if identity else "unknown"
        username = (
            (identity.preferred_username or identity.email)
            if identity else "unknown"
        )
        sub = identity.sub if identity else "unknown"
        groups_claim_name = (oidc_cfg.groups_claim if oidc_cfg else "groups")
        claims: dict = {}
        if identity:
            claims = identity.raw_claims if identity.raw_claims else {
                "sub": identity.sub,
                "email": identity.email,
                "preferred_username": identity.preferred_username,
                f"{groups_claim_name} (parsed as groups)": identity.groups,
            }
        claims_json = _html.escape(_json.dumps(claims, indent=2, default=str))
        html_out = _DENIED_HTML.format(
            email=_html.escape(email),
            username=_html.escape(username),
            sub=_html.escape(sub),
            groups_claim=_html.escape(groups_claim_name),
            claims_json=claims_json,
        )
        return Response(content=html_out, status_code=403, media_type="text/html")

    @app.get("/auth/me", tags=["auth"])
    async def auth_me(request: Request) -> JSONResponse:
        """Return the current user's identity (for debugging)."""
        identity = _get_identity(request, oidc_cfg, oidc_provider)
        if identity is None:
            return JSONResponse({"authenticated": False}, status_code=401)
        return JSONResponse({
            "authenticated": True,
            "sub": identity.sub,
            "email": identity.email,
            "groups": identity.groups,
            "preferred_username": identity.preferred_username,
        })

    @app.get("/auth/login", tags=["auth"])
    async def auth_login(request: Request) -> Response:
        """Branded login page shown after explicit logout.

        After the user signs out the gateway redirects here rather than
        straight to the IdP, so they see a clear \"Sign in with Microsoft\"
        call-to-action instead of a confusing native CloudStack login form.
        """
        # If the user somehow already has a valid session, send them straight
        # to the SPA rather than making them click the button again.
        if oidc_provider is not None:
            identity = _get_identity(request, oidc_cfg, oidc_provider)
            if identity is not None:
                return RedirectResponse(url="/client/", status_code=302)
        next_path = request.query_params.get("next", "/client/")
        error = request.query_params.get("error", "")
        return Response(
            content=_make_login_page(next_path, error),
            media_type="text/html",
        )

    @app.get("/auth/start", tags=["auth"])
    async def auth_start(request: Request) -> Response:
        """Begin the OIDC Authorization Code flow.

        The \"Sign in with Microsoft\" button on /auth/login links here.
        Optional ?next=<path> is preserved through the state parameter and
        used as the post-authentication redirect target.
        """
        if oidc_provider is None:
            return JSONResponse(
                {"error": "OIDC not configured"},
                status_code=501,
            )
        # Loop detection: stop after 3 failed/abandoned attempts
        attempts = int(request.cookies.get("_oidc_attempts", "0"))
        if attempts >= 3:
            resp = RedirectResponse(url="/auth/login?error=loop", status_code=302)
            resp.delete_cookie("_oidc_attempts", path="/")
            return resp
        next_path = request.query_params.get("next", "/client/")
        try:
            auth_url = await oidc_provider.authorization_redirect_url(next_path)
        except Exception as exc:
            logger.error("Failed to build OIDC auth URL: %s", exc)
            return JSONResponse({"error": "OIDC provider unavailable"}, status_code=503)
        resp = RedirectResponse(url=auth_url, status_code=302)
        resp.set_cookie("_oidc_attempts", str(attempts + 1), max_age=600,
                        httponly=True, samesite="lax", path="/")
        return resp

    # ------------------------------------------------------------------
    # Main proxy catch-all
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Dedicated SPA entry-point — guaranteed footer injection
    # ------------------------------------------------------------------
    # The catch-all proxy also attempts footer injection but this specific
    # route is the belt-and-suspenders guarantee: the first thing the
    # browser requests after the bridge-page redirect is GET /client/,
    # and we intercept it here to reliably inject the identity footer.

    @app.get("/client", tags=["proxy"])
    @app.get("/client/", tags=["proxy"])
    async def serve_client_index(request: Request) -> Response:
        """Proxy the CloudStack SPA index page and inject the identity footer."""
        identity = _get_identity(request, oidc_cfg, oidc_provider)
        if identity is None:
            if oidc_provider is not None:
                # Serve a micro-page instead of a bare 302 so JavaScript can
                # capture window.location.hash (never sent to the server) and
                # stash it in a short-lived cookie before the redirect fires.
                # A cookie (not sessionStorage) is used because Firefox clears
                # sessionStorage when the tab navigates to a cross-origin page
                # (the IdP) and back — the cookie survives that round-trip.
                _cl_hash_page = (
                    "<!DOCTYPE html><html><head>"
                    "<meta charset=UTF-8></head><body><script>"
                    "(function(){"
                    "var h=window.location.hash;"
                    "if(h&&h!=='#'&&h!=='#/'&&h.indexOf('#/user/login')===-1){"
                    "document.cookie='_gw_hash='+encodeURIComponent(h)+'; path=/; samesite=lax; max-age=600';}"
                    "window.location.replace('/auth/login?next=/client/');"
                    "})();"
                    "</script></body></html>"
                )
                return Response(
                    content=_cl_hash_page,
                    media_type="text/html",
                    status_code=200,
                )
            return JSONResponse({"error": "Not authenticated"}, status_code=401)

        # Fetch the SPA HTML from upstream
        response = await _proxy_request(request, "client/", config)

        # Inject footer into the HTML (identity always available here;
        # provisioned may be in cache — look it up if so)
        if (
            response.status_code == 200
            and b"<!doctype" in response.body[:200].lower()
        ):
            cache_key = identity.cache_key()
            cached = await cache.get(cache_key)
            _provisioned = cached.provisioned if cached else None
            _injected = _inject_footer(response.body, identity, _provisioned, ui_config=config.ui)
            _inject_headers = {
                k: v for k, v in response.headers.items()
                if k.lower() not in ("content-length", "content-encoding", "cache-control", "expires", "pragma")
            }
            # Prevent browser caching of the SPA shell so our footer injection
            # (hashchange listener, identity bar) is always present.  Without
            # this, a cached pre-proxy version of /client/ has no footer script
            # and the SPA's logout never triggers our /auth/logout redirect.
            _inject_headers["cache-control"] = "no-store"
            response = Response(
                content=_injected,
                status_code=200,
                headers=_inject_headers,
                media_type="text/html",
            )
        return response

    # ------------------------------------------------------------------
    # Catch-all reverse proxy
    # ------------------------------------------------------------------

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
    async def proxy(path: str, request: Request) -> Response:
        # 0. Intercept CloudStack native-auth commands that must not be exposed
        #    when running in OIDC mode.  These commands either have no meaning
        #    (logout — the SPA would purge the session and push /user/login) or
        #    are actively dangerous (forgotPassword/resetPassword let users set
        #    arbitrary passwords on shared CS accounts).
        if oidc_provider is not None:
            _cmd_intercept = request.query_params.get("command", "")
            if not _cmd_intercept and request.method == "POST":
                # POST body params — read without consuming
                try:
                    _body_intercept = await request.body()
                    from urllib.parse import parse_qs as _pqs
                    _bparams = _pqs(_body_intercept.decode(errors="ignore"))
                    _cmd_intercept = (_bparams.get("command", [""])[0])
                except Exception:
                    pass
            if _cmd_intercept.lower() in ("logout", "forgotpassword", "resetpassword", "login"):
                logger.info("Intercepting native CS command '%s' — OIDC mode", _cmd_intercept)
                if _cmd_intercept.lower() == "login":
                    # Reject native CS login attempts — users must authenticate
                    # via OIDC.  Return 401 JSON so the SPA shows an error rather
                    # than silently doing nothing.
                    return JSONResponse(
                        {"loginresponse": {"errorcode": 401, "errortext": "Please use the SSO/OIDC login method."}},
                        status_code=401,
                    )
                if _cmd_intercept.lower() == "logout":
                    # Delete all session cookies server-side so the session is
                    # immediately invalid.  The SPA's axios gets JSON success and
                    # navigates to #/user/login; the footer script detects this
                    # and calls window.location.replace('/auth/logout').
                    # Even if the footer script fails (race, caching), the next
                    # full page load will hit serve_client_index which will
                    # redirect to /auth/login (no valid session cookie remains).
                    _logout_resp = JSONResponse(
                        {"logoutresponse": {"description": "success", "type": "logoutresponse"}},
                        status_code=200,
                    )
                    if oidc_cfg is not None:
                        _logout_resp.delete_cookie(oidc_cfg.session_cookie_name, path="/")
                    _logout_resp.delete_cookie("sessionkey", path="/")
                    _logout_resp.delete_cookie("JSESSIONID", path="/")
                    _logout_resp.delete_cookie("userid", path="/")
                    _logout_resp.delete_cookie("isSAML", path="/")
                    _logout_resp.delete_cookie("_oidc_attempts", path="/")
                    # Signal the footer JS to redirect to /auth/logout.
                    # The footer polls for this cookie every 100 ms.
                    _logout_resp.set_cookie(
                        "_gw_logout_pending", "1",
                        max_age=30, path="/", httponly=False, samesite="lax",
                    )
                    return _logout_resp
                # forgotPassword / resetPassword: silently succeed so SPA doesn't
                # show an error, but do nothing — passwords on shared accounts are
                # managed by the gateway.
                return JSONResponse({"success": True}, status_code=200)

        # 1. Read identity from signed session cookie
        identity = _get_identity(request, oidc_cfg, oidc_provider)
        if identity is None:
            if oidc_provider is None:
                # No OIDC configured — old header-based fallback for dev/testing
                identity = _parse_identity_headers(request, config)
            if identity is None:
                if oidc_provider is not None:
                    # For browser navigations (HTML accepts) send to our login page;
                    # for XHR/API calls return 401 so the SPA can handle it.
                    accept = request.headers.get("accept", "")
                    if "text/html" in accept:
                        import urllib.parse as _uparse
                        import json as _json2
                        _next = f"/{path}"
                        if request.url.query:
                            _next += f"?{request.url.query}"
                        _login_url = f"/auth/login?next={_uparse.quote(_next, safe='/')}"
                        # Serve a micro-page instead of a bare 302 so we can
                        # capture window.location.hash (never sent to server)
                        # and stash it in sessionStorage before the redirect.
                        _hash_redirect_page = (
                            "<!DOCTYPE html><html><head>"
                            "<meta charset=UTF-8></head><body><script>"
                            "(function(){"
                            "var h=window.location.hash;"
                            "if(h&&h!=='#'&&h!=='#/'&&h.indexOf('#/user/login')===-1){"
                            "document.cookie='_gw_hash='+encodeURIComponent(h)+'; path=/; samesite=lax; max-age=600';}"
                            f"window.location.replace({_json2.dumps(_login_url)});"
                            "})();"
                            "</script></body></html>"
                        )
                        return Response(
                            content=_hash_redirect_page,
                            media_type="text/html",
                            status_code=200,
                        )
                    return JSONResponse({"error": "Not authenticated"}, status_code=401)
                return JSONResponse(
                    {"error": "Not authenticated. Configure OIDC or supply identity headers."},
                    status_code=401,
                )

        # 2. Cache check
        cache_key = identity.cache_key()
        cached = await cache.get(cache_key)
        new_cs_session: dict[str, str] = {}  # populated on cache miss if CS login succeeds
        if cached is not None:
            logger.debug("Cache hit for %s", identity.sub)
            provisioned = cached.provisioned
        else:
            # 3. Provision
            logger.info("Provisioning CloudStack objects for user %s", identity.sub)
            try:
                provisioned = await provisioner.provision(identity)
            except CloudStackError as exc:
                logger.error("Provisioning failed for %s: %s", identity.sub, exc)
                return JSONResponse(
                    {"error": "Provisioning failed", "detail": str(exc)},
                    status_code=502,
                )
            except Exception as exc:
                logger.exception("Unexpected provisioning error for %s", identity.sub)
                return JSONResponse(
                    {"error": "Internal provisioning error", "detail": str(exc)},
                    status_code=500,
                )

            # 4. Store in cache
            entry = CacheEntry(
                identity=identity,
                provisioned=provisioned,
                groups_hash=identity.groups_hash(),
            )
            await cache.set(cache_key, entry)

            # 4b. Re-establish CS session so the SPA's cookies remain valid.
            #
            # The CS session (JSESSIONID / sessionkey) set during the original
            # OIDC callback can become stale when the gateway restarts (cache
            # cleared) or the cache TTL expires.  When that happens the next
            # request triggers a cache miss here.  We redo the CS login and:
            #   a) replace the stale sessionkey in the CURRENT upstream request
            #      (so it doesn't bounce with HTTP 432 right now), and
            #   b) attach fresh Set-Cookie headers to the response so the
            #      browser updates its stored cookies for all future requests.
            new_cs_session: dict[str, str] = {}
            if provisioned.user_id and provisioned.user_slug:
                try:
                    _temp_pass = secrets.token_urlsafe(16)
                    await cs_client.update_user(provisioned.user_id, password=_temp_pass)
                    _cs_info, _cs_cookies = await cs_client.login_user(
                        provisioned.user_slug,
                        _temp_pass,
                        domain_id=provisioned.domain_id if provisioned.domain_id else None,
                    )
                    new_cs_session = {
                        "sessionkey": _cs_info.get("sessionkey") or _cs_cookies.get("sessionkey", ""),
                        "userid": str(_cs_info.get("userid", "")),
                        "JSESSIONID": _cs_cookies.get("JSESSIONID", ""),
                    }
                    logger.info(
                        "CS session refreshed for %s (cache miss, cookies: %s)",
                        identity.sub, [k for k, v in new_cs_session.items() if v],
                    )
                except Exception as _exc:
                    logger.warning(
                        "Could not refresh CS session for %s: %s — "
                        "browser may need to re-login",
                        identity.sub, _exc,
                    )

        # 5a. Short-circuit readyForShutdown — CloudStack returns HTTP 431
        #     (request headers too large) for this polling call, which makes the
        #     SPA think the server is shutting down and adds a 25 px banner that
        #     shifts the native header below our replacement bar.  We always
        #     answer "not shutting down".  This MUST run before the permission
        #     check so non-admin users are not blocked by a 403.
        _cmd = request.query_params.get("command", "")
        if _cmd in {"readyForShutdown", "readyForMaintenance"}:
            return Response(
                content='{"readyforshutdownresponse":{"readyforshutdown":false}}',
                media_type="application/json",
                status_code=200,
            )

        # 5. Permission check (proxy tier) — only when OIDC is active
        if oidc_provider is not None:
            command = request.query_params.get("command", "")
            if command:
                domain_name = request.query_params.get("domain") or None
                # Resolve projectid → project_key via the provisioned user's map
                project_key: str | None = None
                project_id_param = request.query_params.get("projectid", "")
                if project_id_param:
                    for pk, pid in provisioned.project_ids.items():
                        if pid == project_id_param:
                            project_key = pk
                            break
                parsed_groups = parse_groups(identity.groups)
                if not check_permission(
                    parsed_groups,
                    command,
                    domain_name=domain_name,
                    project_key=project_key,
                ):
                    logger.warning(
                        "Permission denied for %s: command=%s domain=%s project=%s",
                        identity.sub, command, domain_name, project_key,
                    )
                    return JSONResponse(
                        {"error": "Permission denied", "command": command},
                        status_code=403,
                    )

        # 5b. Intercept listProjects: reply via the proxy's admin client so the
        #     project selector always reflects the user's actual access, regardless
        #     of which domain their CS account is placed in.
        #     Admins (root or domain): return all projects globally.
        #     Project-only users: return only projects they are a member of.
        if _cmd == "listProjects":
            try:
                if provisioned.is_admin:
                    _all_proj = await cs_client.list_projects()
                elif provisioned.project_ids:
                    _all_proj = []
                    for _pid in set(provisioned.project_ids.values()):
                        _all_proj.extend(await cs_client.list_projects(id=_pid))
                else:
                    _all_proj = []
                return JSONResponse({
                    "listprojectsresponse": {
                        "count": len(_all_proj),
                        "project": _all_proj,
                    }
                })
            except Exception as _proj_exc:
                logger.warning(
                    "listProjects intercept failed (%s) — falling through to upstream",
                    _proj_exc,
                )

        # 6. Proxy upstream
        response = await _proxy_request(request, path, config, fresh_cs_session=new_cs_session or None)

        # 6a. Filter listApis response: strip commands the user's role shouldn't see.
        #     The SPA seeds primate__APIS from this call — unknown commands have
        #     no buttons rendered, complementing the proxy-tier permission check.
        if (
            _cmd == "listApis"
            and response.status_code == 200
            and oidc_provider is not None
            and config.ui.hide_commands
        ):
            _role_type = _get_role_type(parse_groups(identity.groups))
            _cmds_hide = set(
                config.ui.hide_commands.get("*", []) +
                config.ui.hide_commands.get(_role_type, [])
            )
            if _cmds_hide:
                try:
                    import json as _japi
                    _jbody = _japi.loads(response.body)
                    _api_list = _jbody.get("listapisresponse", {}).get("api", [])
                    _filtered = [a for a in _api_list if a.get("name") not in _cmds_hide]
                    _jbody["listapisresponse"]["api"] = _filtered
                    _jbody["listapisresponse"]["count"] = len(_filtered)
                    response = Response(
                        content=_japi.dumps(_jbody),
                        status_code=200,
                        media_type="application/json",
                    )
                    logger.debug(
                        "listApis filter: removed %d commands for role %s",
                        len(_api_list) - len(_filtered), _role_type,
                    )
                except Exception:
                    pass  # if parsing fails, return unfiltered response

        # Log non-200 responses and key API calls for debugging
        command = request.query_params.get("command", "")
        if command or "config.json" in path:
            logger.info(
                "PROXY %s /%s → %s (command=%r)",
                request.method, path, response.status_code, command,
            )
        elif response.status_code >= 400:
            logger.warning(
                "PROXY %s /%s → %s",
                request.method, path, response.status_code,
            )

        # 7. Inject fresh CS session cookies when we just re-established the
        #    session.  This updates the browser's stored cookies so that all
        #    subsequent SPA XHR requests use the new sessionkey.
        _is_secure = oidc_cfg is not None and (oidc_cfg.redirect_uri or "").startswith("https")
        if new_cs_session:
            if new_cs_session.get("JSESSIONID"):
                response.set_cookie(
                    "JSESSIONID", new_cs_session["JSESSIONID"],
                    path="/", httponly=True, samesite="lax", secure=_is_secure,
                )
            if new_cs_session.get("sessionkey"):
                response.set_cookie(
                    "sessionkey", new_cs_session["sessionkey"],
                    path="/", httponly=False, samesite="lax", secure=_is_secure,
                )
            if new_cs_session.get("userid"):
                response.set_cookie(
                    "userid", new_cs_session["userid"],
                    path="/", httponly=False, samesite="lax", secure=_is_secure,
                )

        # 8. If CloudStack returned 401 on an API call, the SPA's axios handler
        #    would call Logout() and push to /user/login — bad UX.  Instead,
        #    intercept 401s here: re-establish the CS session and serve a
        #    refresh bridge page that updates localStorage then reloads.
        #    Only do this when OIDC is active (we have an identity) and the
        #    request looks like an interactive XHR (has a command= param).
        if (
            response.status_code == 401
            and oidc_provider is not None
            and identity is not None
            and command
            and request.headers.get("accept", "").lower() != "application/json"
        ):
            logger.info(
                "CS 401 for %s on command=%s — attempting silent re-auth",
                identity.sub, command,
            )
            reauth_session: dict[str, str] = {}
            if provisioned.user_id and provisioned.user_slug:
                try:
                    _tp = secrets.token_urlsafe(16)
                    await cs_client.update_user(provisioned.user_id, password=_tp)
                    _ri, _rc = await cs_client.login_user(
                        provisioned.user_slug, _tp,
                        domain_id=provisioned.domain_id if provisioned.domain_id else None,
                    )
                    reauth_session = {
                        "sessionkey": _ri.get("sessionkey") or _rc.get("sessionkey", ""),
                        "userid": str(_ri.get("userid", "")),
                        "JSESSIONID": _rc.get("JSESSIONID", ""),
                    }
                    logger.info("Silent re-auth succeeded for %s", identity.sub)
                except Exception as _exc:
                    logger.warning("Silent re-auth failed for %s: %s", identity.sub, _exc)
                    # The CS user may have been deleted (stale cache). Invalidate
                    # and re-provision so the account is recreated, then retry.
                    try:
                        logger.info(
                            "Stale cache detected for %s — re-provisioning", identity.sub
                        )
                        await cache.delete(cache_key)
                        provisioned = await provisioner.provision(identity)
                        _new_entry = CacheEntry(
                            identity=identity,
                            provisioned=provisioned,
                            groups_hash=identity.groups_hash(),
                        )
                        await cache.set(cache_key, _new_entry)
                        if provisioned.user_id and provisioned.user_slug:
                            _tp2 = secrets.token_urlsafe(16)
                            await cs_client.update_user(provisioned.user_id, password=_tp2)
                            _ri2, _rc2 = await cs_client.login_user(
                                provisioned.user_slug, _tp2,
                                domain_id=provisioned.domain_id if provisioned.domain_id else None,
                            )
                            reauth_session = {
                                "sessionkey": _ri2.get("sessionkey") or _rc2.get("sessionkey", ""),
                                "userid": str(_ri2.get("userid", "")),
                                "JSESSIONID": _rc2.get("JSESSIONID", ""),
                            }
                            logger.info(
                                "Silent re-auth succeeded after re-provision for %s", identity.sub
                            )
                    except Exception as _exc2:
                        logger.warning(
                            "Re-provision also failed for %s: %s", identity.sub, _exc2
                        )

            if reauth_session.get("sessionkey"):
                # Retry the original request transparently with the new
                # session — this way the SPA never sees a 401 and doesn't
                # fall back to the login page.
                reauth_resp = await _proxy_request(
                    request, path, config,
                    fresh_cs_session=reauth_session,
                )
                if reauth_session.get("JSESSIONID"):
                    reauth_resp.set_cookie("JSESSIONID", reauth_session["JSESSIONID"],
                        path="/", httponly=True, samesite="lax", secure=_is_secure)
                reauth_resp.set_cookie("sessionkey", reauth_session["sessionkey"],
                    path="/", httponly=False, samesite="lax", secure=_is_secure)
                if reauth_session.get("userid"):
                    reauth_resp.set_cookie("userid", reauth_session["userid"],
                        path="/", httponly=False, samesite="lax", secure=_is_secure)
                return reauth_resp

        # 9. Inject identity footer into HTML page responses so users can
        #    always see which OIDC account they're operating under.
        _ct = response.headers.get("content-type", "")
        if (
            oidc_provider is not None
            and identity is not None
            and "text/html" in _ct
            and response.status_code == 200
            # Only inject into full-page loads, not API JSON responses.
            # Case-insensitive: CS serves <!doctype html> (lowercase).
            and b"<!doctype" in response.body[:200].lower()
        ):
            _injected = _inject_footer(response.body, identity, provisioned, ui_config=config.ui)
            _inject_headers = {
                k: v for k, v in response.headers.items()
                if k.lower() not in ("content-length", "content-encoding")
            }
            response = Response(
                content=_injected,
                status_code=response.status_code,
                headers=_inject_headers,
                media_type=_ct,
            )

        return response

    return app


# ---------------------------------------------------------------------------
# Identity helpers
# ---------------------------------------------------------------------------

def _get_identity(
    request: Request,
    oidc_cfg: "AppConfig.model_fields['oidc'].annotation | None",  # type: ignore[type-arg]
    oidc_provider: OidcProvider | None,
) -> OidcIdentity | None:
    """Extract OidcIdentity from the signed session cookie, or None if absent/expired."""
    if oidc_cfg is None or oidc_provider is None:
        return None
    cookie_value = request.cookies.get(oidc_cfg.session_cookie_name, "")
    if not cookie_value:
        return None
    return oidc_provider.parse_session_cookie(cookie_value)


def _parse_identity_headers(request: Request, config: AppConfig) -> OidcIdentity | None:
    """Fallback: extract OIDC identity from oauth2-proxy forwarded headers.

    Only used when no OidcProvider is configured (dev / legacy header-injection mode).
    """
    oidc = config.oidc
    if oidc is None:
        # Try a minimal set of well-known headers
        sub = request.headers.get("x-forwarded-user", "").strip()
        if not sub:
            return None
        email = request.headers.get("x-forwarded-email", "").strip()
        preferred_username = request.headers.get("x-forwarded-preferred-username", "").strip()
        groups_raw = request.headers.get("x-forwarded-groups", "").strip()
        groups = [g.strip() for g in groups_raw.split(",") if g.strip()]
        return OidcIdentity(sub=sub, email=email, preferred_username=preferred_username, groups=groups)

    sub = request.headers.get("x-forwarded-user", "").strip()
    if not sub:
        return None
    email = request.headers.get("x-forwarded-email", "").strip()
    preferred_username = request.headers.get("x-forwarded-preferred-username", "").strip()
    groups_raw = request.headers.get("x-forwarded-groups", "").strip()
    groups: list[str] = []
    if groups_raw:
        groups = [g.strip() for g in groups_raw.split(",") if g.strip()]
    return OidcIdentity(sub=sub, email=email, preferred_username=preferred_username, groups=groups)


# ---------------------------------------------------------------------------
# Reverse proxy helper
# ---------------------------------------------------------------------------

async def _proxy_request(
    request: Request,
    path: str,
    config: AppConfig,
    *,
    fresh_cs_session: dict[str, str] | None = None,
) -> Response:
    """Forward the request to the CloudStack upstream.

    If *fresh_cs_session* is supplied (keys: ``sessionkey``, ``userid``,
    ``JSESSIONID``), the stale values in the outgoing Cookie header and
    ``sessionkey`` query parameter are replaced so the current request
    reaches CloudStack with a valid session even when the browser's stored
    cookies are stale.
    """
    upstream_url = config.server.upstream_url.rstrip("/")
    target_url = f"{upstream_url}/{path}"

    # Preserve query string, optionally replacing stale sessionkey
    qs = request.url.query
    if qs:
        if fresh_cs_session and fresh_cs_session.get("sessionkey") and "sessionkey" in qs:
            # Parse and surgically replace the stale sessionkey so the
            # current request is not rejected with HTTP 432.
            from urllib.parse import urlencode, parse_qsl as _parse_qsl
            _params = [(k, fresh_cs_session["sessionkey"] if k == "sessionkey" else v)
                       for k, v in _parse_qsl(qs, keep_blank_values=True)]
            qs = urlencode(_params)
        target_url = f"{target_url}?{qs}"

    # Build forwarded headers (drop hop-by-hop and inject CS keys)
    # Also strip our own session cookie — CloudStack must never see it, both
    # because it is meaningless to CloudStack and because it can be several KB
    # (Entra tokens are large) which causes Jetty to return 431.
    session_cookie_name = (
        config.oidc.session_cookie_name if config.oidc else "oidcgw_session"
    )
    headers: dict[str, str] = {}
    for k, v in request.headers.items():
        if k.lower() in _HOP_BY_HOP:
            continue
        if k.lower() == "cookie":
            # Strip our session cookie; optionally replace stale CS session
            # cookies with fresh values so the current upstream request succeeds.
            parts: list[str] = []
            _fresh_jses = fresh_cs_session.get("JSESSIONID", "") if fresh_cs_session else ""
            _fresh_sk = fresh_cs_session.get("sessionkey", "") if fresh_cs_session else ""
            for _part in v.split(";"):
                _part = _part.strip()
                if not _part:
                    continue
                if _part.startswith(f"{session_cookie_name}="):
                    continue  # always strip our own auth cookie
                if _fresh_jses and _part.startswith("JSESSIONID="):
                    parts.append(f"JSESSIONID={_fresh_jses}")
                    _fresh_jses = ""  # only inject once
                    continue
                if _fresh_sk and _part.startswith("sessionkey="):
                    parts.append(f"sessionkey={_fresh_sk}")
                    _fresh_sk = ""  # only inject once
                    continue
                parts.append(_part)
            # Append if not already present (browser might not have them yet)
            if fresh_cs_session:
                if fresh_cs_session.get("JSESSIONID") and _fresh_jses:
                    parts.append(f"JSESSIONID={fresh_cs_session['JSESSIONID']}")
                if fresh_cs_session.get("sessionkey") and _fresh_sk:
                    parts.append(f"sessionkey={fresh_cs_session['sessionkey']}")
            if parts:
                headers[k] = "; ".join(parts)
            # If the only cookie was ours, omit the Cookie header entirely.
        else:
            headers[k] = v

    body = await request.body()

    async with httpx.AsyncClient(
        verify=config.cloudstack.verify_ssl,
        timeout=config.cloudstack.timeout,
        follow_redirects=False,  # Pass redirects to the browser; see Location rewrite below
    ) as client:
        proxy_response = await client.request(
            method=request.method,
            url=target_url,
            headers=headers,
            content=body,
        )

    # httpx automatically decompresses gzip/deflate bodies, so the decompressed
    # content length no longer matches the upstream Content-Length / Content-Encoding
    # headers.  Drop both so FastAPI recalculates the correct Content-Length.
    # For redirect responses we also must NOT drop content-encoding (body is empty),
    # but we do need to rewrite the Location header so it points at the proxy, not
    # the upstream backend.  Without this the browser would follow the redirect
    # directly to the backend IP, bypassing the proxy entirely.
    _DROP_RESPONSE_HEADERS = frozenset({"content-encoding", "content-length", "transfer-encoding"})
    response_headers: dict[str, str] = {}
    for k, v in proxy_response.headers.items():
        if k.lower() in _DROP_RESPONSE_HEADERS:
            continue
        if k.lower() == "location":
            # Rewrite absolute upstream URLs (http://192.168.0.144:8080/client/...)
            # to proxy-relative paths (/client/...) so the browser follows the
            # redirect back through the proxy rather than hitting the backend directly.
            if v.startswith(upstream_url):
                v = v[len(upstream_url):] or "/"
            elif v.startswith("http://") or v.startswith("https://"):
                # Cross-origin redirect: keep only path + query
                import urllib.parse as _urlparse
                _p = _urlparse.urlparse(v)
                v = _p.path + (f"?{_p.query}" if _p.query else "")
        response_headers[k] = v
    return Response(
        content=proxy_response.content,
        status_code=proxy_response.status_code,
        headers=response_headers,
        media_type=proxy_response.headers.get("content-type"),
    )
