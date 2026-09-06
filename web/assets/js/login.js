/* Reference login for a passkey gate.
   The page holds no secret. It asks the service for a challenge, lets the browser sign it,
   and hands the signature back; the service sets the session cookie. Everything the visitor
   sees is one sentence saying where they are in that ceremony. */
(function () {
  var say = document.getElementById("say"),
      acts = document.getElementById("acts"),
      keyBtn = document.getElementById("key"),
      altBtn = document.getElementById("alt"),
      backBtn = document.getElementById("back"),
      form = document.getElementById("code"),
      hint = document.getElementById("hint"),
      cond = document.getElementById("cond"),
      slots = [1, 2, 3, 4].map(function (n) { return document.getElementById("w" + n); });

  var params = new URLSearchParams(location.search);
  var linkCode = (location.hash.match(/[#&]i=([^&]+)/) || [])[1];
  var canPasskey = !!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.get);
  var busy = false, conditional = null;

  /* ---------- what the page says ---------- */
  function tell(text, wrong) {
    say.textContent = text;
    say.classList.toggle("wrong", !!wrong);
  }
  function greet(name) {
    say.textContent = "";
    say.appendChild(document.createTextNode("Welcome back, "));
    var b = document.createElement("span");
    b.className = "name";
    b.textContent = name;
    say.appendChild(b);
    say.appendChild(document.createTextNode("."));
    say.classList.remove("wrong");
  }

  /* ---------- talking to the service ---------- */
  function api(path, body) {
    return fetch("/_auth/" + path, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-Doorman-Request": "1" },
      body: JSON.stringify(body || {})
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) {
        j.ok = r.ok; j.status = r.status; return j;
      });
    }).catch(function () { return { ok: false, status: 0, offline: true }; });
  }

  /* WebAuthn speaks ArrayBuffers; the wire speaks base64url. */
  function b2a(s) {
    var t = s.replace(/-/g, "+").replace(/_/g, "/");
    var b = atob(t.padEnd(Math.ceil(t.length / 4) * 4, "="));
    var u = new Uint8Array(b.length);
    for (var i = 0; i < b.length; i++) u[i] = b.charCodeAt(i);
    return u.buffer;
  }
  function a2b(buf) {
    var u = new Uint8Array(buf), s = "";
    for (var i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function toGet(o) {
    return Object.assign({}, o, {
      challenge: b2a(o.challenge),
      allowCredentials: (o.allowCredentials || []).map(function (c) { return Object.assign({}, c, { id: b2a(c.id) }); })
    });
  }
  function toCreate(o) {
    return Object.assign({}, o, {
      challenge: b2a(o.challenge),
      user: Object.assign({}, o.user, { id: b2a(o.user.id) }),
      excludeCredentials: (o.excludeCredentials || []).map(function (c) { return Object.assign({}, c, { id: b2a(c.id) }); })
    });
  }
  function fromCred(c) {
    var r = c.response, j = {
      id: c.id, rawId: a2b(c.rawId), type: c.type,
      clientExtensionResults: c.getClientExtensionResults ? c.getClientExtensionResults() : {},
      response: { clientDataJSON: a2b(r.clientDataJSON) }
    };
    if (r.attestationObject) {
      j.response.attestationObject = a2b(r.attestationObject);
      j.response.transports = r.getTransports ? r.getTransports() : [];
    } else {
      j.response.authenticatorData = a2b(r.authenticatorData);
      j.response.signature = a2b(r.signature);
      j.response.userHandle = r.userHandle ? a2b(r.userHandle) : null;
    }
    if (c.authenticatorAttachment) j.authenticatorAttachment = c.authenticatorAttachment;
    return j;
  }

  /* ---------- where we go afterwards ----------
     `next` comes from the address bar, so it is attacker-controlled. Accept only a path on
     this origin, or an https URL on this site's own domain. Everything else goes to the root. */
  function dest() {
    var next = params.get("next");
    if (!next || /\\/.test(next) || /^\/\//.test(next)) return "/";
    try {
      var u = new URL(next, location.href);
      if (/(^|\/)index\.html$/.test(u.pathname)) return "/";
      if (u.protocol === location.protocol && u.host === location.host) {
        return /^\/\//.test(u.pathname) ? "/" : u.pathname + u.search + u.hash;
      }
      var root = location.hostname.split(".").slice(-2).join(".");
      if (u.protocol === "https:" && !u.username && !u.password &&
          (u.hostname === root || u.hostname.endsWith("." + root))) return u.href;
    } catch (e) {}
    return "/";
  }

  function through(name) {
    document.body.classList.add("through");
    if (name) greet(name); else tell("You're in.");
    acts.hidden = true; form.hidden = true;
    setTimeout(function () { location.href = dest(); }, 700);
  }

  /* ---------- the passkey path ---------- */
  function usePasskey(auto) {
    if (!canPasskey || busy) return;
    if (!auto && conditional) { conditional.abort(); conditional = null; }
    if (!auto) busy = true;

    api("login/options").then(function (o) {
      if (!o.ok) {
        if (!auto) { tell(o.status === 429 ? "Too many tries. Wait a moment." : "Couldn't start. Try again.", true); busy = false; }
        return;
      }
      var req = { publicKey: toGet(o.options) };
      if (auto) { conditional = new AbortController(); req.mediation = "conditional"; req.signal = conditional.signal; }
      else tell("Waiting for your key…");

      return navigator.credentials.get(req).then(function (cred) {
        if (!cred) { busy = false; return; }
        tell("Checking.");
        return api("login/verify", { challenge_id: o.challenge_id, credential: fromCred(cred) }).then(function (v) {
          busy = false;
          if (v.ok) return through(v.name);
          tell(v.status === 429 ? "Too many tries. Wait a moment." : "That key wasn't recognised.", true);
        });
      });
    }).catch(function () {
      busy = false;
      if (!auto) tell("That key wasn't recognised.", true);
    });
  }

  /* ---------- the invite path ---------- */
  function redeem(code) {
    acts.hidden = true; form.hidden = true;
    tell("Checking your code.");
    api("invite/redeem", { code: code }).then(function (r) {
      if (r.status === 429) return offer("Too many tries. Wait a moment.", true);
      if (r.status === 403) return offer("That invite is full. Ask for a new one.", true);
      if (!r.ok) return offer("That code didn't work.", true);
      if (!r.ticket) return through(null);

      /* A member's first visit: redeem, then make a key on the spot. */
      tell("Making a key for " + r.name + ".");
      if (!canPasskey) return offer("This browser can't make a passkey. Open the link on your phone.", true);
      api("register/options", { ticket: r.ticket }).then(function (o) {
        if (!o.ok) return offer("That invite has expired. Ask for a new one.", true);
        return navigator.credentials.create({ publicKey: toCreate(o.options) }).then(function (cred) {
          return api("register/verify", {
            challenge_id: o.challenge_id, ticket: r.ticket,
            credential: fromCred(cred), label: (navigator.platform || "").slice(0, 40)
          }).then(function (v) {
            if (v.ok) return through(v.name);
            offer("That key didn't save. Your invite is still good — reload to try again.", true);
          });
        });
      }).catch(function () {
        offer("No key was made. Your invite is still good — reload to try again.", true);
      });
    });
  }

  /* Put the visitor back in front of a choice after something went wrong. */
  function offer(message, wrong) {
    tell(message, wrong);
    if (canPasskey) { acts.hidden = false; form.hidden = true; }
    else { form.hidden = false; acts.hidden = true; slots[0].focus(); }
  }

  /* ---------- the code slots ----------
     A code is three words and two digits. The field has that shape, so a paste falls into
     place and a typo is visible before it is submitted. */
  function spread(text) {
    var parts = String(text).trim().toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
    if (parts.length < 2) return false;
    slots.forEach(function (el, i) { el.value = parts[i] || ""; });
    slots[Math.min(parts.length, 4) - 1].focus();
    return true;
  }
  function code() {
    return slots.map(function (el) { return el.value.trim().toLowerCase(); }).filter(Boolean).join("-");
  }
  slots.forEach(function (el, i) {
    el.addEventListener("paste", function (e) {
      var text = (e.clipboardData || window.clipboardData).getData("text");
      if (spread(text)) e.preventDefault();
    });
    el.addEventListener("input", function () {
      if (/[^a-z0-9]/i.test(el.value)) {           /* typed a separator: move on */
        var rest = el.value.split(/[^a-z0-9]/);
        el.value = rest[0];
        if (i < 3) { slots[i + 1].focus(); slots[i + 1].value = rest.slice(1).join(""); }
        return;
      }
      if (i === 3) el.value = el.value.replace(/\D/g, "").slice(0, 2);
      if (i < 3 && el.value.length >= 9) slots[i + 1].focus();
    });
    el.addEventListener("keydown", function (e) {
      if (e.key === "Backspace" && !el.value && i > 0) { slots[i - 1].focus(); e.preventDefault(); }
    });
  });

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    var c = code();
    if (c.split("-").length < 4) { hint.textContent = "that looks short — three words and two digits"; return; }
    hint.textContent = "paste the whole code and it will fall into place";
    redeem(c);
  });

  keyBtn.addEventListener("click", function () { usePasskey(false); });
  altBtn.addEventListener("click", function () {
    acts.hidden = true; form.hidden = false;
    tell("Enter your invite code.");
    slots[0].focus();
  });
  backBtn.addEventListener("click", function () {
    form.hidden = true; acts.hidden = false;
    tell("Touch your key to continue.");
  });

  /* ---------- arriving ---------- */
  document.getElementById("where").textContent = location.host;

  if (linkCode) {
    /* Arrived by invite link. Take the code out of the address bar before doing anything with it. */
    var c = "";
    try { c = decodeURIComponent(linkCode); } catch (e) {}
    try { history.replaceState(null, "", location.pathname + location.search); } catch (e) {}
    if (location.hash) location.hash = "";
    if (c) { redeem(c); return; }
  }

  if (canPasskey) {
    tell("Touch your key to continue.");
    acts.hidden = false;
    if (window.PublicKeyCredential.isConditionalMediationAvailable) {
      window.PublicKeyCredential.isConditionalMediationAvailable()
        .then(function (yes) { if (yes) usePasskey(true); })
        .catch(function () {});
    }
  } else {
    tell("Enter your invite code.");
    form.hidden = false;
    slots[0].focus();
  }
})();
