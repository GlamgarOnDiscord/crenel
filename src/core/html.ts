// Linear scans of target-controlled text (response bodies up to 2 MB).
//
// A pattern like /<meta[^>]+…url=…/ restarts at every "<meta" and rescans to
// the end of the tag, or of the body when no ">" follows: a page made of
// "<meta" repeats takes quadratic time or worse, and a regex cannot be
// interrupted, so one crafted page (or one stored comment) stalls the whole
// run. These helpers walk the body once: the opener is a literal regex, the
// end of the tag an indexOf.

export interface Tag { text: string; start: number; end: number; closed: boolean }

/** Each tag opened by `opener` (e.g. /<meta/i), as its text up to and including the next ">". An unclosed last tag runs to the end of the body. */
export function* tagsOf(body: string, opener: RegExp): Generator<Tag> {
  const re = new RegExp(opener.source, opener.flags.replace(/[gy]/g, "") + "g");
  let m: RegExpExecArray | null;
  while ((m = re.exec(body))) {
    const gt = body.indexOf(">", m.index + m[0].length);
    if (gt === -1) { yield { text: body.slice(m.index), start: m.index, end: body.length, closed: false }; return; }
    yield { text: body.slice(m.index, gt + 1), start: m.index, end: gt + 1, closed: true };
    re.lastIndex = gt + 1;
  }
}

/** The last of the non-overlapping matches of `re` in `s` (what a greedy `[^>]+` placed before it would pick). */
export function lastMatch(s: string, re: RegExp): RegExpExecArray | null {
  const g = new RegExp(re.source, re.flags.replace(/[gy]/g, "") + "g");
  let m: RegExpExecArray | null, last: RegExpExecArray | null = null;
  while ((m = g.exec(s))) { last = m; if (m[0] === "") g.lastIndex++; }
  return last;
}

/** The body of each <script …>…</script>, in order. */
export function* scriptBlocks(body: string): Generator<string> {
  const open = /<script\b/gi, close = /<\/script>/gi;
  let m: RegExpExecArray | null;
  while ((m = open.exec(body))) {
    const gt = body.indexOf(">", m.index + m[0].length);
    if (gt === -1) return;
    close.lastIndex = gt + 1;
    const c = close.exec(body);
    if (!c) return; // no later block can close either
    yield body.slice(gt + 1, c.index);
    open.lastIndex = c.index + c[0].length;
  }
}

/** The URL of a <meta http-equiv=refresh …url=…> (same reading as
 * /<meta[^>]+http-equiv=["']?refresh["']?[^>]+url=([^"'>\s]+)/i), or null. */
export function metaRefreshUrl(body: string): string | null {
  for (const t of tagsOf(body, /<meta/i)) {
    const eq = /http-equiv=["']?refresh/gi;
    eq.lastIndex = 6; // `<meta[^>]+`: at least one character after "<meta"
    const e = eq.exec(t.text);
    if (!e) continue;
    // `["']?[^>]+`: at least one character (the quote counts) before url=.
    const u = lastMatch(t.text.slice(e.index + e[0].length + 1), /url=([^"'>\s]+)/i);
    if (u) return u[1]!;
  }
  return null;
}
