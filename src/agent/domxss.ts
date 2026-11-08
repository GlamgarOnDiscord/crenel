// DOM-based XSS detection for the exploration layer (explore.dom-xss).
//
// Reflected/stored oracles read the HTTP body, so they miss XSS that only fires
// when the browser executes JavaScript (payload reflected into a DOM sink by the
// page's own script). The only honest proof of DOM XSS is to RUN the page in a
// real browser and observe the injected script execute. We do exactly that, with
// a unique nonce: the payload calls alert(nonce); if a dialog with that nonce
// fires, the script ran — proven. No signature, and no false positive (a page
// that escapes or never reaches the sink never fires the dialog).
//
// The browser is OPTIONAL: Playwright is imported dynamically. Without it (or a
// chromium), the validator reports "unavailable" and the claim stays a lead, so
// Crenel's core keeps no hard dependency on a browser.

export interface DomXssResult { available: boolean; executed: boolean; reason: string }

/** Load `url` in headless chromium and report whether a dialog carrying `nonce` fired. */
export async function proveDomXss(url: string, nonce: string, opts?: { playwrightPath?: string; executablePath?: string; timeoutMs?: number }): Promise<DomXssResult> {
  const pwPath = opts?.playwrightPath ?? process.env.CRENEL_PLAYWRIGHT ?? "playwright";
  let chromium: { launch: (o?: unknown) => Promise<unknown> };
  try {
    ({ chromium } = (await import(pwPath)) as { chromium: { launch: (o?: unknown) => Promise<unknown> } });
  } catch {
    return { available: false, executed: false, reason: "no browser: install playwright (or set CRENEL_PLAYWRIGHT) to prove DOM XSS" };
  }
  const exe = opts?.executablePath ?? process.env.CRENEL_BROWSER;
  const timeoutMs = opts?.timeoutMs ?? 15_000;
  let browser: { newPage: () => Promise<Page>; close: () => Promise<void> } | undefined;
  type Page = { on: (ev: string, fn: (d: { message?: () => string; accept: () => Promise<void> }) => void) => void; goto: (u: string, o?: unknown) => Promise<unknown>; waitForTimeout: (ms: number) => Promise<void> };
  try {
    browser = (await chromium.launch(exe ? { executablePath: exe } : {})) as typeof browser;
    const page = await browser!.newPage();
    let fired = false;
    page.on("dialog", (d) => { try { if ((d.message?.() ?? "") === nonce) fired = true; } catch { /* */ } void d.accept(); });
    try { await page.goto(url, { waitUntil: "networkidle", timeout: timeoutMs }); } catch { /* a slow/hung page can still have fired */ }
    await page.waitForTimeout(600);
    return { available: true, executed: fired, reason: fired ? "the injected script executed in the browser (alert with our nonce)" : "no script execution observed in the browser" };
  } catch (e) {
    return { available: false, executed: false, reason: `browser error: ${(e as Error).message}` };
  } finally {
    try { await browser?.close(); } catch { /* */ }
  }
}

/** The payload to inject so a DOM sink executes alert(nonce). Kept broad but generic. */
export function domXssPayload(nonce: string): string {
  return `"><img src=x onerror="alert('${nonce}')">`;
}
