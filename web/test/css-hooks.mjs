// Node loader hooks for the SSR smoke test: stylesheets (plain and CSS
// modules) are a Vite concern, so under Node they load as an empty module
// whose default export echoes class names.
export async function load(url, context, nextLoad) {
  if (url.endsWith(".css")) {
    return {
      format: "module",
      shortCircuit: true,
      source: "export default new Proxy({}, { get: (_, k) => (typeof k === 'string' ? k : undefined) });",
    };
  }
  return nextLoad(url, context);
}
