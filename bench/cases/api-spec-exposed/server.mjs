// An API that publishes its OpenAPI document at the framework default path,
// and answers /openapi.json with an unrelated JSON status object.
import { createServer } from "node:http";

const spec = {
  openapi: "3.0.1",
  info: { title: "billing-api", version: "1" },
  paths: {
    "/invoices/{invoiceId}": { get: {} },
    "/admin/accounts/{accountId}": { get: {}, delete: {} },
    "/admin/refunds": { post: {} },
  },
};

export default () => createServer((req, res) => {
  const json = (b) => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(b)); };
  if (req.url === "/v3/api-docs") return json(spec);
  if (req.url === "/openapi.json") return json({ status: "ok", openapi: "disabled" });
  res.writeHead(404); res.end();
});
