/* Reference admin for doorman.
   Everything the CLI's owner commands do, without typing them: who can get in, what each person
   can reach, how long they have, and letting someone new in.

   The page holds no authority. Every route below re-checks on the server that the caller is the
   owner on a passkey session, so a saved copy of this file is worth nothing to anyone. Point it at
   your own site list by editing SITES. */
(function () {
  var SITES = ["notes", "photos", "files", "archive"];
  var TTLS = ["7d", "30d", "90d"];

  var $ = function (id) { return document.getElementById(id); };
  var say = $("say"), rows = $("rows"), people = $("people"), askBox = $("askBox"),
      handoff = $("handoff"), form = $("askForm"), who = $("who"), chips = $("chips"),
      ttlBar = $("ttls"), note = $("askNote"), copied = $("copied");

  var kind = "guest", ttl = "7d", picked = [], me = null;

  /* ---------- talking to the service ---------- */
  function api(path, body) {
    var init = body === undefined
      ? { credentials: "same-origin" }
      : { method: "POST", credentials: "same-origin",
          headers: { "Content-Type": "application/json", "X-Doorman-Request": "1" },
          body: JSON.stringify(body) };
    return fetch("/_auth/" + path, init).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) {
        j.ok = r.ok; j.status = r.status; return j;
      });
    }).catch(function () { return { ok: false, status: 0, error: "the service is not answering" }; });
  }

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  }
  function day(ts) { return ts ? new Date(ts * 1000).toDateString().slice(4, 10) : ""; }
  function has(list, v) { return list.indexOf(v) !== -1; }

  /* ---------- a person's state, in one line of prose ---------- */
  function state(p) {
    if (p.disabled) return "revoked";
    var live = null, bits = [];
    for (var i = 0; i < p.invites.length; i++) if (p.invites[i].active) live = p.invites[i];
    if (live && live.max_browsers > 1) bits.push(live.browsers_used + " of " + live.max_browsers + " browsers");
    else if (live) bits.push("invite unused");
    if (p.passkeys) bits.push(p.passkeys + (p.passkeys === 1 ? " key" : " keys"));
    /* browsers-used already counts the sessions an invite produced, so only say it when there is none */
    if (!live && p.sessions.length) bits.push(p.sessions.length + (p.sessions.length === 1 ? " session" : " sessions"));
    if (live) bits.push("until " + day(live.expires));
    return bits.length ? bits.join("  ·  ") : "nothing yet";
  }

  /* ---------- the list ---------- */
  function load() {
    return Promise.all([api("me"), api("admin/guests")]).then(function (r) {
      var mine = r[0], guests = r[1];
      if (!mine.ok) return refuse("You are not signed in.");
      me = mine;
      if (!guests.ok) return refuse(guests.status === 403 ? "Only the owner can open this page." : (guests.error || "The service refused."));

      say.textContent = "Who can get in.";
      say.classList.remove("wrong");
      rows.textContent = "";
      rows.appendChild(person({ name: me.name, role: me.role, disabled: false, passkeys: null,
                                sessions: [], invites: [], sites: me.sites, self: true }));
      guests.guests.forEach(function (p) { rows.appendChild(person(p)); });
      people.hidden = false; askBox.hidden = false; handoff.hidden = true;
      buildChips();
    });
  }

  function refuse(message) {
    say.textContent = message;
    say.classList.add("wrong");
    people.hidden = true; askBox.hidden = true;
  }

  function person(p) {
    var li = el("li", "who" + (p.disabled ? " gone" : ""));

    var nm = el("div", "nm");
    nm.appendChild(el("span", "n", p.name));           /* the strike belongs on the name, not the role beside it */
    nm.appendChild(el("span", "role", p.self ? "you" : p.role));
    li.appendChild(nm);

    var meta = el("p", "meta");
    if (has(p.sites, "*")) meta.appendChild(el("span", "sites", "everything"));
    else if (!p.sites.length) meta.appendChild(el("span", "sites", "no sites"));
    else meta.appendChild(el("span", "sites", p.sites.join("  ")));
    if (!p.self) { meta.appendChild(document.createTextNode("  ·  ")); meta.appendChild(document.createTextNode(state(p))); }
    li.appendChild(meta);

    var acts = el("div", "acts");
    if (!p.self) {
      acts.appendChild(button("Sites", function () { sitesDrawer(li, p); }, false));
      acts.appendChild(button("Time", function () { timeDrawer(li, p); }, p.disabled));
      acts.appendChild(button(p.disabled ? "Revoked" : "Revoke", function () { revokeDrawer(li, p); }, p.disabled));
    }
    li.appendChild(acts);
    return li;
  }

  function button(label, onClick, disabled) {
    var b = el("button", "alt", label);
    b.type = "button";
    b.disabled = !!disabled;
    if (!disabled) b.addEventListener("click", onClick);
    return b;
  }

  /* A row carries at most one drawer. The button that opened it closes it again; a different
     button swaps it, rather than stacking two under the same person. */
  function drawer(li, kindName) {
    var open = li.querySelector(".drawer");
    if (open) {
      var same = open.dataset.kind === kindName;
      li.removeChild(open);
      if (same) return null;
    }
    var box = el("div", "drawer");
    box.dataset.kind = kindName;
    li.appendChild(box);
    return box;
  }

  /* ---------- what one person can reach ---------- */
  function sitesDrawer(li, p) {
    var box = drawer(li, "sites"); if (!box) return;
    var hint = el("p", "hint", "Click a site to give it to " + p.name + " or take it away.");
    var bar = el("div", "chips");
    SITES.forEach(function (s) {
      var c = el("button", "chip" + (has(p.sites, s) ? " on" : ""), s);
      c.type = "button";
      c.addEventListener("click", function () {
        c.disabled = true;
        var giving = !has(p.sites, s);
        api("admin/sites", giving ? { name: p.name, grant: [s] } : { name: p.name, deny: [s] }).then(function (r) {
          c.disabled = false;
          if (!r.ok) { hint.textContent = r.error || "That did not take."; box.classList.add("warn"); return; }
          p.sites = r.sites || [];
          c.classList.toggle("on", has(p.sites, s));
          box.classList.remove("warn");
          hint.textContent = p.name + " can reach " + (p.sites.length ? p.sites.join(", ") : "nothing") + ".";
          li.querySelector(".meta .sites").textContent = p.sites.length ? p.sites.join("  ") : "no sites";
        });
      });
      bar.appendChild(c);
    });
    box.appendChild(hint); box.appendChild(bar);
  }

  /* ---------- how much longer ----------
     The reason this exists rather than just re-inviting: nothing is sent. Their invite and every
     browser they are already signed in on move to the same date, and they notice nothing. */
  function timeDrawer(li, p) {
    var box = drawer(li, "time"); if (!box) return;
    var hint = el("p", "hint", "How much longer for " + p.name + "? Nothing is sent — they keep working.");
    var bar = el("div", "chips");
    TTLS.forEach(function (t) {
      var c = el("button", "chip", t);
      c.type = "button";
      c.addEventListener("click", function () {
        Array.prototype.forEach.call(bar.children, function (b) { b.disabled = true; });
        api("admin/extend", { name: p.name, ttl: t }).then(function (r) {
          Array.prototype.forEach.call(bar.children, function (b) { b.disabled = false; });
          if (!r.ok) { hint.textContent = r.error || "That did not take."; box.classList.add("warn"); return; }
          box.classList.remove("warn");
          hint.textContent = r.moved
            ? p.name + " is good until " + day(r.expires) + "."
            : p.name + " already had longer — until " + day(r.expires) + ".";
          load();
        });
      });
      bar.appendChild(c);
    });
    box.appendChild(hint); box.appendChild(bar);
  }

  /* ---------- revoking ----------
     The one thing here that a click cannot undo, so it asks first. A member with a passkey gets
     the choice that actually matters: keep the key and they can be let back in later, or remove it
     and they need a fresh invite. A guest's key is always dropped, so there is nothing to ask. */
  function revokeDrawer(li, p) {
    var box = drawer(li, "revoke"); if (!box) return;
    var keeps = p.role === "member" && p.passkeys;
    var hint = el("p", "hint", keeps
      ? "Revoke " + p.name + "? Their sessions end either way."
      : "Revoke " + p.name + "? Their sessions and code stop working.");
    var bar = el("div", "chips");

    function go(keys, btn) {
      Array.prototype.forEach.call(bar.children, function (b) { b.disabled = true; });
      btn.textContent = "…";
      api("admin/revoke", { name: p.name, keys: keys }).then(function (r) {
        if (!r.ok) { hint.textContent = r.error || "That did not take."; box.classList.add("warn"); return; }
        load();
      });
    }
    if (keeps) {
      var keep = el("button", "chip", "Revoke, keep their key"); keep.type = "button";
      keep.addEventListener("click", function () { go(false, keep); });
      var drop = el("button", "chip danger", "Revoke and remove their key"); drop.type = "button";
      drop.addEventListener("click", function () { go(true, drop); });
      bar.appendChild(keep); bar.appendChild(drop);
    } else {
      var yes = el("button", "chip danger", "Revoke " + p.name); yes.type = "button";
      yes.addEventListener("click", function () { go(true, yes); });
      bar.appendChild(yes);
    }
    var no = el("button", "chip", "Leave them alone"); no.type = "button";
    no.addEventListener("click", function () { li.removeChild(box); });
    bar.appendChild(no);

    box.appendChild(hint); box.appendChild(bar);
  }

  /* ---------- letting someone in ---------- */
  function buildChips() {
    chips.textContent = "";
    SITES.forEach(function (s) {
      var c = el("button", "chip" + (has(picked, s) ? " on" : ""), s);
      c.type = "button";
      c.addEventListener("click", function () {
        if (has(picked, s)) picked.splice(picked.indexOf(s), 1); else picked.push(s);
        c.classList.toggle("on", has(picked, s));
        note.textContent = picked.length === 1 ? "One site, so the link lands them straight on it." : "";
      });
      chips.appendChild(c);
    });
    ttlBar.textContent = "";
    TTLS.forEach(function (t) {
      var c = el("button", "chip" + (t === ttl ? " on" : ""), t);
      c.type = "button";
      c.addEventListener("click", function () {
        ttl = t;
        Array.prototype.forEach.call(ttlBar.children, function (b) { b.classList.toggle("on", b.textContent === t); });
      });
      ttlBar.appendChild(c);
    });
  }

  [["kGuest", "guest"], ["kMember", "member"]].forEach(function (pair) {
    $(pair[0]).addEventListener("click", function () {
      kind = pair[1];
      $("kGuest").classList.toggle("on", kind === "guest");
      $("kMember").classList.toggle("on", kind === "member");
    });
  });

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    if (!who.value.trim()) { note.textContent = "Give them a name."; return; }
    if (!picked.length) { note.textContent = "Pick at least one site."; return; }
    note.textContent = "Asking…";
    api("admin/invite", { name: who.value.trim().toLowerCase(), sites: picked.slice(), ttl: ttl, kind: kind })
      .then(function (r) {
        if (!r.ok) { note.textContent = r.error || "That did not take."; return; }
        show(r);
      });
  });

  /* ---------- the handoff. Shown once, so it takes the page. ---------- */
  function show(r) {
    people.hidden = true; askBox.hidden = true; handoff.hidden = false;
    say.textContent = "Hand this over.";
    $("handoffWho").textContent = r.name + "  ·  " + r.kind + "  ·  " + (r.sites || []).join(" ") + "  ·  until " + day(r.expires);
    $("codeBig").textContent = r.code;
    $("codeLink").textContent = r.link;
    copied.textContent = "";
    function copy(text, said) {
      return function () {
        navigator.clipboard.writeText(text)
          .then(function () { copied.textContent = said; })
          .catch(function () { copied.textContent = "Couldn't copy — select it by hand."; });
      };
    }
    $("copyCode").onclick = copy(r.code, "Code copied.");
    $("copyLink").onclick = copy(r.link, "Link copied.");
  }

  $("doneHandoff").addEventListener("click", function () {
    who.value = ""; picked = []; note.textContent = "";
    load();
  });

  document.getElementById("where").textContent = location.host;
  load();
})();
