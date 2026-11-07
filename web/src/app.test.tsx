import { test } from "node:test";
import assert from "node:assert/strict";
import React from "react";
import { renderToString } from "react-dom/server";
import { createMemoryRouter, RouterProvider } from "react-router-dom";
import { routes } from "./App.tsx";

// Server-render each route to confirm every page mounts without throwing. CSS is
// imported only in main.tsx, so pages render under Node without a DOM. This is a
// smoke test, not a hydration test; useLayoutEffect SSR warnings are expected.
const PATHS = [
  "/",
  "/app/overview",
  "/app/findings",
  "/app/findings/f-stripe",
  "/app/scans",
  "/app/scan/run",
  "/app/targets",
  "/app/onboarding",
  "/app/secrets",
  "/app/authz",
  "/app/tests",
  "/app/integrations",
  "/app/settings",
];

for (const path of PATHS) {
  test(`route ${path} renders without throwing`, () => {
    const router = createMemoryRouter(routes, { initialEntries: [path] });
    const html = renderToString(React.createElement(RouterProvider, { router }));
    assert.ok(html.length > 50, `expected markup for ${path}`);
  });
}
