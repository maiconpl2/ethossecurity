// Fixture for src/ethossecurity/rules/semgrep/js-web.yaml (React + TypeScript, Next.js / React Router).
import { useEffect, useRef, useState } from "react";
import { useParams, useSearchParams } from "react-router-dom";
import { jwtDecode } from "jwt-decode";
import { useQuery } from "react-query";
import DOMPurify from "dompurify";

type Claims = { sub: string; name: string };

export function SearchResults() {
  const [searchParams] = useSearchParams();
  const term = searchParams.get("term") ?? "";
  return (
    <div>
      <p
        // ruleid: ethos.js.dom-xss-untrusted-source, ethos.js.react-dangerously-set-inner-html
        dangerouslySetInnerHTML={{ __html: `You searched for <b>${term}</b>` }}
      />
      <p
        // ok: ethos.js.dom-xss-untrusted-source, ethos.js.react-dangerously-set-inner-html
        dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(term) }}
      />
      <p title={term}>You searched for {term}</p>
    </div>
  );
}

export function PostPage({ getPost }: { getPost: (slug: string) => { content: string; title: string } }) {
  const { slug } = useParams();
  const post = getPost(slug ?? "");
  return (
    <main>
      <div
        // ok: ethos.js.dom-xss-untrusted-source
        // ruleid: ethos.js.react-dangerously-set-inner-html
        dangerouslySetInnerHTML={{ __html: post.content }}
      />
      <div
        // ruleid: ethos.js.dom-xss-untrusted-source, ethos.js.react-dangerously-set-inner-html
        dangerouslySetInnerHTML={{ __html: `<h1>${slug}</h1>` }}
      />
    </main>
  );
}

export function PostById({ fetchPost }: { fetchPost: (id: string) => Promise<{ body: string }> }) {
  const { id } = useParams();
  const { data } = useQuery(["post", id], () => fetchPost(id ?? ""));
  return (
    <div
      // ok: ethos.js.dom-xss-untrusted-source
      // ruleid: ethos.js.react-dangerously-set-inner-html
      dangerouslySetInnerHTML={{ __html: data?.body ?? "" }}
    />
  );
}

export function EmbeddedCheckout({ token }: { token: string }) {
  const frameRef = useRef<HTMLIFrameElement>(null);
  const [status, setStatus] = useState<string>("idle");

  useEffect(() => {
    const handleMessage = (event: MessageEvent) => {
      setStatus(event.data.status);
    };
    // ruleid: ethos.js.message-listener-no-origin-check
    window.addEventListener("message", handleMessage);
    return () => window.removeEventListener("message", handleMessage);
  }, []);

  useEffect(() => {
    const onCheckoutMessage = (event: MessageEvent) => {
      if (event.origin !== "https://checkout.example.com") return;
      setStatus(event.data.status);
    };
    // ok: ethos.js.message-listener-no-origin-check
    window.addEventListener("message", onCheckoutMessage);
    return () => window.removeEventListener("message", onCheckoutMessage);
  }, []);

  const sendToken = () => {
    // ruleid: ethos.js.postmessage-wildcard-origin
    frameRef.current?.contentWindow?.postMessage({ type: "init", token }, "*");
    // ok: ethos.js.postmessage-wildcard-origin
    frameRef.current?.contentWindow?.postMessage({ type: "init", token }, "https://checkout.example.com");
  };

  return <iframe ref={frameRef} onLoad={sendToken} title={status} src="https://checkout.example.com" />;
}

export function useCurrentUser(): Claims | null {
  const token = localStorage.getItem("accessToken");
  // Client-side decoding only for display (no request handler) is not reported.
  return token ? jwtDecode<Claims>(token) : null;
}

export function saveSession(accessToken: string, theme: string) {
  // ruleid: ethos.js.token-in-browser-storage
  localStorage.setItem("accessToken", accessToken);
  // ok: ethos.js.token-in-browser-storage
  localStorage.setItem("preferredTheme", theme);
}

export function inviteLink(): string {
  // ruleid: ethos.js.insecure-random-secret
  const inviteCode: string = Math.random().toString(36).slice(2, 10);
  // ok: ethos.js.insecure-random-secret
  const animationJitter: number = Math.random() * 20;
  return `${inviteCode}-${animationJitter}`;
}

// Next.js App Router page: searchParams comes from the URL.
export default function SearchPage({ searchParams }: { searchParams: { q?: string } }) {
  // ruleid: ethos.js.dom-xss-untrusted-source, ethos.js.react-dangerously-set-inner-html
  return <p dangerouslySetInnerHTML={{ __html: `You searched: ${searchParams.q}` }} />;
}

// Hono JSX and the html`` tag escape interpolated values; a plain template string does not.
export function registerHonoRoutes(app: { get: Function }, html: Function) {
  app.get("/hi0", (c: any) => {
    const who = c.req.query("who");
    // ruleid: ethos.js.reflected-xss-from-request
    return c.html(`<h1>Hello ${who}</h1>`);
  });
  app.get("/hi", (c: any) => {
    const who = c.req.query("who");
    // ok: ethos.js.reflected-xss-from-request
    return c.html(<h1>Hello {who}</h1>);
  });
  app.get("/hi2", (c: any) => {
    const who = c.req.query("who");
    // ok: ethos.js.reflected-xss-from-request
    return c.html(html`<h1>Hello ${who}</h1>`);
  });
}
