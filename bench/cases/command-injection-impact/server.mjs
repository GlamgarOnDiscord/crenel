// A sink that evaluates a shell-ish payload (so command injection is provable) AND
// exposes a /flag readable through the same channel — to verify the opt-in impact
// sample captures it. Mini shell: echo X (with $((7*7))->49), id, cat /flag*.
import { createServer } from "node:http";
const FLAG = "FLAG{crenel-impact-demo-7f3a}";
function sh(cmd) {
  return cmd.split(";").map((part) => {
    const c = part.trim();
    if (/^echo\s+/.test(c)) return c.replace(/^echo\s+/, "").replace(/\$\(\(7\*7\)\)/g, "49");
    if (c === "id") return "uid=0(root)";
    if (/^cat\s+.*\/flag/.test(c)) return FLAG;
    return "";
  }).filter(Boolean).join("\n");
}
const read = (req) => new Promise((r) => { let b = ""; req.on("data", (x) => (b += x)); req.on("end", () => r(b)); });
export default () => createServer(async (req, res) => {
  let arg = ""; try { arg = (JSON.parse(await read(req)).cmd ?? ""); } catch {}
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify({ out: sh("echo " + arg) })); // the benign value is echoed; injected ; runs more
});
