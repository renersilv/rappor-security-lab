import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";

function fail(message) {
  throw new Error(message);
}

function delay(milliseconds) {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds));
}

async function waitForPage(port) {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    try {
      const pages = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
      const page = pages.find((item) => item.type === "page");
      if (page?.webSocketDebuggerUrl) return page;
    } catch {
      // Chromium may not have opened its local debugging socket yet.
    }
    await delay(100);
  }
  fail("Chromium did not expose a bounded local debugging page");
}

function cdp(webSocket) {
  let nextId = 0;
  const pending = new Map();
  webSocket.addEventListener("message", (event) => {
    const message = JSON.parse(event.data);
    if (!message.id || !pending.has(message.id)) return;
    const item = pending.get(message.id);
    pending.delete(message.id);
    if (message.error) item.reject(new Error(message.error.message));
    else item.resolve(message.result);
  });
  return (method, params = {}) => new Promise((resolvePromise, rejectPromise) => {
    const id = ++nextId;
    pending.set(id, { resolve: resolvePromise, reject: rejectPromise });
    webSocket.send(JSON.stringify({ id, method, params }));
  });
}

function loginExpression(email, password) {
  const credentials = JSON.stringify({ email, password });
  return `(() => {
    const credentials = ${credentials};
    const setValue = (element, value) => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(element, value);
      element.dispatchEvent(new Event("input", { bubbles: true }));
      element.dispatchEvent(new Event("change", { bubbles: true }));
    };
    const email = document.querySelector("input[type=email]");
    const password = document.querySelector("input[type=password]");
    if (!email || !password) return false;
    setValue(email, credentials.email);
    setValue(password, credentials.password);
    email.closest("form")?.requestSubmit();
    return true;
  })()`;
}

export async function probeConnectedServicePresentation({
  baseUrl,
  email,
  password,
  assessmentId,
  locale,
  chromePath = "google-chrome",
  port = 0,
}) {
  if (!new Set(["pt-BR", "en-US"]).has(locale)) fail("unsupported rendered locale");
  if (!/^[0-9a-f]{8}-[0-9a-f-]{27,}$/iu.test(assessmentId ?? "")) fail("invalid assessment identifier");
  const origin = new URL(baseUrl).origin;
  const profile = mkdtempSync("/tmp/rappor-connected-chromium-");
  const selectedPort = port || 19_300 + Math.floor(Math.random() * 300);
  const chrome = spawn(chromePath, [
    "--headless=new",
    "--no-sandbox",
    `--lang=${locale}`,
    `--remote-debugging-port=${selectedPort}`,
    `--user-data-dir=${profile}`,
    `${origin}/login`,
  ], { stdio: "ignore" });
  let webSocket;
  try {
    const page = await waitForPage(selectedPort);
    webSocket = new WebSocket(page.webSocketDebuggerUrl);
    await new Promise((resolvePromise, rejectPromise) => {
      webSocket.addEventListener("open", resolvePromise, { once: true });
      webSocket.addEventListener("error", rejectPromise, { once: true });
    });
    const send = cdp(webSocket);
    await send("Page.enable");
    await send("Network.enable");
    await send("Network.setExtraHTTPHeaders", { headers: { "Accept-Language": `${locale},en;q=0.8` } });
    await delay(1_000);
    const submitted = await send("Runtime.evaluate", {
      expression: loginExpression(email, password),
      returnByValue: true,
    });
    if (submitted.result.value !== true) fail("the rendered login controls were unavailable");
    await delay(2_000);
    await send("Page.navigate", { url: `${origin}/executions/${encodeURIComponent(assessmentId)}` });
    await delay(2_500);
    const expression = `(() => {
      const text = document.body?.innerText || "";
      const language = (document.documentElement.lang || navigator.language || "").toLowerCase();
      const localeText = ${JSON.stringify(locale === "pt-BR")}
        ? /execu[cç][aã]o|cobertura|resultado|falhou|conclu[ií]da|problema/i.test(text)
        : /execution|coverage|result|failed|completed|issue/i.test(text);
      return {
        pathMatches: /^\\/executions\\/[0-9a-f-]{20,}$/i.test(location.pathname),
        loginAbsent: !document.querySelector("input[type=password]"),
        contentRendered: text.trim().length > 80,
        localeMatches: language.startsWith(${JSON.stringify(locale.toLowerCase())}) || localeText,
      };
    })()`;
    const evaluated = await send("Runtime.evaluate", { expression, returnByValue: true });
    const value = evaluated.result.value;
    return {
      locale,
      route: "execution-detail",
      rendered: value?.contentRendered === true && value?.loginAbsent === true,
      navigable: value?.pathMatches === true && value?.localeMatches === true,
    };
  } finally {
    if (webSocket) webSocket.close();
    chrome.kill("SIGTERM");
    await Promise.race([
      new Promise((resolvePromise) => chrome.once("exit", resolvePromise)),
      delay(2_000),
    ]);
    rmSync(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
}
