// Node loader hooks for the SSR smoke test: stylesheets (plain and CSS
// modules) are a Vite concern, so under Node they load as an empty module
// whose default export echoes class names. Vite's `?raw` imports (the
// provider SVGs) load as the file's text, as Vite does.
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

export async function load(url, context, nextLoad) {
  if (url.startsWith("file:") && url.endsWith("?raw")) {
    const text = await readFile(fileURLToPath(url.slice(0, -"?raw".length)), "utf8");
    return { format: "module", shortCircuit: true, source: `export default ${JSON.stringify(text)};` };
  }
  if (url.endsWith(".css")) {
    return {
      format: "module",
      shortCircuit: true,
      source: "export default new Proxy({}, { get: (_, k) => (typeof k === 'string' ? k : undefined) });",
    };
  }
  return nextLoad(url, context);
}
