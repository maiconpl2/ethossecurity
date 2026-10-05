// Fixture for src/ethossecurity/rules/semgrep/js-web.yaml (browser code: vanilla DOM, jQuery, React JSX).
import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/router";
import DOMPurify from "dompurify";
import { marked } from "marked";
import Cookies from "js-cookie";

const escapeHtml = (value) =>
  String(value).replace(/[&<>"']/g, (ch) => `&#${ch.charCodeAt(0)};`);

// ---------------------------------------------------------------------------
// ethos.js.dom-xss-untrusted-source
// ---------------------------------------------------------------------------
export function renderSearchPage() {
  const params = new URLSearchParams(window.location.search);
  const query = params.get("q");
  const resultsEl = document.getElementById("results");
  // ruleid: ethos.js.dom-xss-untrusted-source
  resultsEl.innerHTML = `<h2>Results for ${query}</h2>`;
  // ok: ethos.js.dom-xss-untrusted-source
  resultsEl.textContent = `Results for ${query}`;
  // ok: ethos.js.dom-xss-untrusted-source
  resultsEl.innerHTML = DOMPurify.sanitize(params.get("html"));
  // ok: ethos.js.dom-xss-untrusted-source
  document.title = encodeURIComponent(query);
}

export function renderWelcome(translations) {
  const params = new URLSearchParams(window.location.search);
  const lang = params.get("lang");
  const page = Number(params.get("page") ?? 1);
  const banner = document.getElementById("welcome");
  // The parameter only selects an existing entry, and numbers cannot carry markup.
  // ok: ethos.js.dom-xss-untrusted-source
  banner.innerHTML = translations[lang].welcome;
  // ok: ethos.js.dom-xss-untrusted-source
  banner.innerHTML = `<span>Page ${page}</span>`;
}

export function showReferralBanner() {
  // ruleid: ethos.js.dom-xss-untrusted-source
  document.write("<p>Invited by " + decodeURIComponent(location.hash.slice(1)) + "</p>");
}

export function showFlashMessage() {
  // ruleid: ethos.js.dom-xss-untrusted-source
  $("#flash").html(new URL(location.href).searchParams.get("msg"));
}

export function greetFromWindowName() {
  const banner = document.querySelector(".banner");
  // ruleid: ethos.js.dom-xss-untrusted-source
  banner.insertAdjacentHTML("afterbegin", `<b>Welcome back, ${window.name}</b>`);
}

document.addEventListener("DOMContentLoaded", () => {
  const tab = new URLSearchParams(location.search).get("tab");
  const header = document.querySelector("#tab-title");
  // ruleid: ethos.js.dom-xss-untrusted-source
  header.innerHTML = `<h1>${tab}</h1>`;
});

export async function showItemFromQuery() {
  const id = new URLSearchParams(location.search).get("id");
  const res = await fetch(`/api/items/${id}`);
  const item = await res.json();
  const detail = document.getElementById("detail");
  // The URL only selects the record; rendering API data is reported by the unescaped-html rule instead.
  // ok: ethos.js.dom-xss-untrusted-source
  // ruleid: ethos.js.dom-xss-unescaped-html
  detail.innerHTML = item.description;
  const stats = await (await fetch(`/api/stats/${id}`)).json();
  // ok: ethos.js.dom-xss-untrusted-source, ethos.js.dom-xss-unescaped-html
  detail.querySelector(".total").innerHTML = stats.total;
}

// ruleid: ethos.js.message-listener-no-origin-check
window.addEventListener("message", (event) => {
  const chatBox = document.getElementById("chat");
  // ruleid: ethos.js.dom-xss-untrusted-source
  chatBox.insertAdjacentHTML("beforeend", event.data.html);
});

// ok: ethos.js.message-listener-no-origin-check
window.addEventListener("message", (event) => {
  if (event.origin !== "https://widgets.example.com") return;
  const preview = document.getElementById("preview");
  // ok: ethos.js.dom-xss-untrusted-source, ethos.js.dom-xss-unescaped-html
  preview.innerHTML = event.data.html;
});

// ruleid: ethos.js.message-listener-no-origin-check
window.addEventListener("message", ({ data }) => {
  const toast = document.querySelector(".toast");
  // ruleid: ethos.js.dom-xss-untrusted-source
  toast.innerHTML = data.message;
});

// ok: ethos.js.message-listener-no-origin-check
window.addEventListener("message", ({ origin, data }) => {
  if (origin !== "https://widgets.example.com") return;
  const toast = document.querySelector(".toast");
  // ok: ethos.js.dom-xss-untrusted-source
  toast.innerHTML = DOMPurify.sanitize(data.message);
});

export function renderFilters(el) {
  const filters = Object.fromEntries(new URLSearchParams(window.location.search));
  // ruleid: ethos.js.dom-xss-untrusted-source, ethos.js.dom-xss-unescaped-html
  el.innerHTML = `<h2>Category: ${filters.category}</h2>`;
  const { searchParams } = new URL(window.location.href);
  const ref = searchParams.get("ref");
  // ruleid: ethos.js.dom-xss-untrusted-source
  el.insertAdjacentHTML("beforeend", `<small>Referred by ${ref}</small>`);
}

export function NextSearchBanner() {
  const { query } = useRouter();
  const banner = document.getElementById("banner");
  // ruleid: ethos.js.dom-xss-untrusted-source, ethos.js.dom-xss-unescaped-html
  banner.innerHTML = `<p>You searched for ${query.q}</p>`;
  return null;
}

export function renderPagerAndEscapes(nav, page) {
  const params = new URLSearchParams(window.location.search);
  params.set("page", String(page + 1));
  // URLSearchParams serialization is percent-encoded and cannot break out of the attribute.
  // ok: ethos.js.dom-xss-untrusted-source, ethos.js.dom-xss-unescaped-html
  nav.innerHTML = `<a class="next" href="?${params.toString()}">Next</a>`;
  const q = params.get("q") ?? "";
  // ok: ethos.js.dom-xss-untrusted-source
  nav.innerHTML = `<p>${q.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")}</p>`;
  const signIn = new URLSearchParams({ client_id: "web", response_type: "code" });
  // ok: ethos.js.dom-xss-untrusted-source
  nav.innerHTML = `<a href="https://auth.example.com/authorize?${signIn}">Sign in</a>`;
  // ok: ethos.js.dom-xss-untrusted-source
  nav.innerHTML = decodeURIComponent("%3Cb%3EWelcome%3C%2Fb%3E");
}

// ---------------------------------------------------------------------------
// ethos.js.dom-xss-unescaped-html
// ---------------------------------------------------------------------------
export function renderTodos(todos, count) {
  const list = document.querySelector("#todo-list");
  // ruleid: ethos.js.dom-xss-unescaped-html
  list.innerHTML = todos.map((todo) => `<li class="todo">${todo.text}</li>`).join("");
  // ok: ethos.js.dom-xss-unescaped-html
  list.innerHTML = todos.map((todo) => `<li class="todo">${escapeHtml(todo.text)}</li>`).join("");
  const counter = document.querySelector("#counter");
  // ok: ethos.js.dom-xss-unescaped-html
  counter.innerHTML = `<strong>${count}</strong> items left (${todos.length} total)`;
  // ok: ethos.js.dom-xss-unescaped-html
  counter.innerHTML = "";
}

export function renderComments(comments) {
  let html = "";
  for (const c of comments) {
    html += "<div class='comment'><b>" + c.author + "</b></div>";
  }
  const commentsEl = document.getElementById("comments");
  // ruleid: ethos.js.dom-xss-unescaped-html
  commentsEl.innerHTML = html;
  // ok: ethos.js.dom-xss-unescaped-html
  commentsEl.innerHTML = DOMPurify.sanitize(html);
}

export function renderNotifications(notifications) {
  let markup = "";
  notifications.forEach((n) => {
    markup += `<div class="notification">${n.sender}: ${n.preview}</div>`;
  });
  const panel = document.getElementById("notifications");
  // ruleid: ethos.js.dom-xss-unescaped-html
  panel.innerHTML = markup;
  let safeMarkup = "";
  notifications.forEach((n) => {
    safeMarkup += `<div class="notification">${escapeHtml(n.sender)} (${n.unreadCount})</div>`;
  });
  // ok: ethos.js.dom-xss-unescaped-html
  panel.innerHTML = safeMarkup;
}

export async function loadProfile(userId) {
  const res = await fetch(`/api/users/${userId}`);
  const user = await res.json();
  const profileEl = document.getElementById("profile");
  // ruleid: ethos.js.dom-xss-unescaped-html
  profileEl.innerHTML = user.bio;
  // ok: ethos.js.dom-xss-unescaped-html
  profileEl.querySelector(".name").textContent = user.name;
}

export function addToCart(item, isOnline) {
  // ruleid: ethos.js.dom-xss-unescaped-html
  $("#cart").append(`<li>${item.name} - ${item.price}</li>`);
  const statusEl = document.getElementById("status");
  // ok: ethos.js.dom-xss-unescaped-html
  statusEl.innerHTML = `<span class="${isOnline ? "online" : "offline"}">${ICONS.dot}</span>`;
}

export function renderMarkdownPreview(textarea) {
  const preview = document.getElementById("md-preview");
  // ruleid: ethos.js.dom-xss-unescaped-html
  preview.innerHTML = marked.parse(textarea.value);
  // ok: ethos.js.dom-xss-unescaped-html
  preview.innerHTML = DOMPurify.sanitize(marked.parse(textarea.value));
}

// Game/timer numbers, caught errors, static CONSTANT data and data-* attributes are not user HTML.
export function startTimer(timerEl, statusEl) {
  let minutes = 0;
  let seconds = 0;
  setInterval(async () => {
    seconds += 1;
    // ok: ethos.js.dom-xss-unescaped-html
    timerEl.innerHTML = `<b>${minutes}</b>:<b>${seconds}</b>`;
    try {
      await fetch("/api/tick", { method: "POST" });
    } catch (err) {
      // ok: ethos.js.dom-xss-unescaped-html
      statusEl.innerHTML = err.message;
    }
  }, 1000);
}

export function buildNav(nav, counter) {
  // ok: ethos.js.dom-xss-unescaped-html
  nav.innerHTML = NAV_ITEMS.map((item) => `<a href="${item.href}">${item.label}</a>`).join("");
  const suffix = counter.getAttribute("data-suffix") || "";
  // ok: ethos.js.dom-xss-unescaped-html
  counter.innerHTML = `<span class="value">${Number(counter.textContent)}</span>${suffix}`;
}

// ---------------------------------------------------------------------------
// ethos.js.react-dangerously-set-inner-html
// ---------------------------------------------------------------------------
export function BlogPost({ post, markdown }) {
  const clean = useMemo(() => DOMPurify.sanitize(post.content), [post.content]);
  const jsonLd = { "@context": "https://schema.org", "@type": "BlogPosting", headline: post.title };
  return (
    <article>
      <script
        type="application/ld+json"
        // ok: ethos.js.react-dangerously-set-inner-html
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />
      <div
        className="post-body"
        // ruleid: ethos.js.react-dangerously-set-inner-html
        dangerouslySetInnerHTML={{ __html: post.content }}
      />
      <section
        // ruleid: ethos.js.react-dangerously-set-inner-html
        dangerouslySetInnerHTML={{ __html: marked(markdown) }}
      />
      <div
        // ok: ethos.js.react-dangerously-set-inner-html
        dangerouslySetInnerHTML={{ __html: clean }}
      />
      <div
        // ok: ethos.js.react-dangerously-set-inner-html
        dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(post.summary) }}
      />
      <footer
        // ok: ethos.js.react-dangerously-set-inner-html
        dangerouslySetInnerHTML={{ __html: "&copy; 2026 Acme Blog" }}
      />
    </article>
  );
}

export function createMarkup(comment) {
  // ruleid: ethos.js.react-dangerously-set-inner-html
  return { __html: comment.html };
}

export function Preview({ unsafeHtml }) {
  return (
    <section>
      <div
        // ruleid: ethos.js.react-dangerously-set-inner-html
        dangerouslySetInnerHTML={{ __html: unsafeHtml }}
      />
      <script
        // An inline script without interpolation (next-themes style) is a literal.
        // ok: ethos.js.react-dangerously-set-inner-html
        dangerouslySetInnerHTML={{
          __html: `(function () {
            try {
              if (localStorage.getItem("theme") === "dark") document.documentElement.classList.add("dark");
            } catch (e) {}
          })();`,
        }}
      />
    </section>
  );
}

// ---------------------------------------------------------------------------
// ethos.js.postmessage-wildcard-origin
// ---------------------------------------------------------------------------
export function notifyParent(token, height) {
  // ruleid: ethos.js.postmessage-wildcard-origin
  window.parent.postMessage({ type: "auth", token }, "*");
  // ok: ethos.js.postmessage-wildcard-origin
  window.parent.postMessage({ type: "resize", height }, "https://app.example.com");
  // ok: ethos.js.postmessage-wildcard-origin
  window.postMessage({ type: "tick" }, "*");
}

export function sendToPopup(popup, session) {
  // ruleid: ethos.js.postmessage-wildcard-origin
  popup.postMessage(session, { targetOrigin: "*" });
  // ok: ethos.js.postmessage-wildcard-origin
  popup.postMessage(session, { targetOrigin: window.location.origin });
}

export function finishOAuth(accessToken, frame) {
  const payload = { type: "oauth-done", accessToken };
  // ruleid: ethos.js.postmessage-wildcard-origin
  window.opener.postMessage(payload, "*");
  // Size/ready notifications and player commands carry no data.
  // ok: ethos.js.postmessage-wildcard-origin
  window.parent.postMessage({ type: "resize", height: document.body.scrollHeight }, "*");
  // ok: ethos.js.postmessage-wildcard-origin
  frame.contentWindow.postMessage(JSON.stringify({ event: "command", func: "pauseVideo", args: [] }), "*");
}

// ---------------------------------------------------------------------------
// ethos.js.message-listener-no-origin-check
// ---------------------------------------------------------------------------
// ruleid: ethos.js.message-listener-no-origin-check
window.onmessage = function (e) {
  applySettings(e.data);
};

// ok: ethos.js.message-listener-no-origin-check
window.addEventListener("message", () => refreshBadge());

// ok: ethos.js.message-listener-no-origin-check
window.addEventListener("message", function (e) {
  if (!TRUSTED_ORIGINS.includes(e.origin)) {
    return;
  }
  applySettings(e.data);
});

// ---------------------------------------------------------------------------
// ethos.js.token-in-browser-storage
// ---------------------------------------------------------------------------
export async function login(email, password) {
  const res = await fetch("/api/login", { method: "POST", body: JSON.stringify({ email, password }) });
  const data = await res.json();
  // ruleid: ethos.js.token-in-browser-storage
  localStorage.setItem("token", data.token);
  // ruleid: ethos.js.token-in-browser-storage
  window.localStorage.setItem("refreshToken", data.refreshToken);
  // ruleid: ethos.js.token-in-browser-storage
  document.cookie = `jwt=${data.token}; path=/; max-age=3600`;
  // ok: ethos.js.token-in-browser-storage
  localStorage.setItem("theme", "dark");
  // ok: ethos.js.token-in-browser-storage
  localStorage.setItem("authorName", data.user.name);
  // ok: ethos.js.token-in-browser-storage
  localStorage.setItem("tokenExpiresAt", String(data.expiresAt));
  // ruleid: ethos.js.token-in-browser-storage
  sessionStorage.setItem("accessToken", data.accessToken);
  // ruleid: ethos.js.token-in-browser-storage
  Cookies.set("token", data.token, { expires: 7 });
  // ruleid: ethos.js.token-in-browser-storage
  localStorage.setItem("user", JSON.stringify({ ...data.user, token: data.token }));
}

export function logout() {
  // ok: ethos.js.token-in-browser-storage
  document.cookie = "token=; Max-Age=0; path=/";
  // ok: ethos.js.token-in-browser-storage
  localStorage.setItem("user", JSON.stringify({ name: "guest" }));
}

// ---------------------------------------------------------------------------
// ethos.js.insecure-random-secret (browser flavour)
// ---------------------------------------------------------------------------
export function PasswordGenerator() {
  const [password, setPassword] = useState("");
  const generatePassword = (length = 16) => {
    const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%";
    let result = "";
    for (let i = 0; i < length; i++) {
      // ruleid: ethos.js.insecure-random-secret
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    setPassword(result);
  };
  // ok: ethos.js.insecure-random-secret
  const secretNumber = Math.floor(Math.random() * 100) + 1;
  // ok: ethos.js.insecure-random-secret
  const key = Math.random().toString(36).slice(2);
  useEffect(() => generatePassword(), []);
  return <p data-key={key} data-n={secretNumber}>{password}</p>;
}

export const generateSessionToken = () =>
  // ruleid: ethos.js.insecure-random-secret
  [...Array(32)].map(() => Math.random().toString(36)[2]).join("");

export function generateRoomCode() {
  // Public, shareable codes (rooms, short links) are not secrets.
  // ok: ethos.js.insecure-random-secret
  return Math.random().toString(36).slice(2, 7).toUpperCase();
}

// LLM demo: sampling one vocabulary token or a random index is not generating a secret.
export function TokenSampler({ candidates, vocab, tokens }) {
  // ok: ethos.js.insecure-random-secret
  const sampledToken = candidates[Math.floor(Math.random() * candidates.length)];
  // ok: ethos.js.insecure-random-secret
  const randomToken = Math.floor(Math.random() * vocab.length);
  // ok: ethos.js.insecure-random-secret
  const maskedToken = Math.random() < 0.15 ? "[MASK]" : tokens[0];
  // ok: ethos.js.insecure-random-secret
  const step = { token: vocab[Math.floor(Math.random() * vocab.length)], index: randomToken };
  return <p data-step={step.index}>{sampledToken} {maskedToken} {step.token}</p>;
}

export function InviteLink({ alphabet }) {
  // Strings built from many random picks are still secrets.
  // ruleid: ethos.js.insecure-random-secret
  const inviteToken = Array.from({ length: 24 }, () => alphabet[Math.floor(Math.random() * alphabet.length)]).join("");
  let password = "";
  for (let i = 0; i < 16; i++) {
    // ruleid: ethos.js.insecure-random-secret
    password += alphabet[Math.floor(Math.random() * alphabet.length)];
  }
  return <a href={`/invite/${inviteToken}`} data-p={password}>Invite</a>;
}
