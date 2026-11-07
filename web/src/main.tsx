import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { RouterProvider, createHashRouter } from "react-router-dom";
import { routes } from "./App.tsx";
// JetBrains Mono is OFL: bundled, so code renders the same offline.
import "@fontsource/jetbrains-mono/latin-400.css";
import "@fontsource/jetbrains-mono/latin-500.css";
import "@fontsource/jetbrains-mono/latin-700.css";
import "./styles/tw.css";
import "./styles/tokens.css";
import "./styles/base.css";
import "./styles/transitions.css";

// Hash router: the app is a static SPA that must deep-link and screenshot from a
// plain file/preview server without server-side routing.
const router = createHashRouter(routes);

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <RouterProvider router={router} />
  </StrictMode>,
);
