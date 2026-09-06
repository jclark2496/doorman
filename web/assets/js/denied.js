/* The refusal page. `host` comes from the address bar and anyone can link here, so it is
   only ever printed when it is genuinely one of this site's own hosts. Anything else — a
   sentence, a phone number, someone else's domain — becomes a generic phrase. */
(function () {
  var raw = (new URLSearchParams(location.search).get("host") || "").replace(/[^a-z0-9.\-]/gi, "");
  var root = location.hostname.split(".").slice(-2).join(".");
  var ours = new RegExp("^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)?" + root.replace(/\./g, "\\.") + "$", "i");
  var host = ours.test(raw) ? raw : "";

  document.getElementById("where").textContent = location.host;
  document.getElementById("which").textContent = host
    ? host + " is not on your list. Ask whoever invited you."
    : "That site is not on your list. Ask whoever invited you.";
})();
