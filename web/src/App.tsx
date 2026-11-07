import { Navigate, type RouteObject } from "react-router-dom";
import { Shell } from "./components/Shell.tsx";
import { Landing } from "./pages/Landing.tsx";
import { Overview } from "./pages/Overview.tsx";
import { Findings } from "./pages/Findings.tsx";
import { FindingDetail } from "./pages/FindingDetail.tsx";
import { Scans } from "./pages/Scans.tsx";
import { Agent } from "./pages/Agent.tsx";
import { Targets } from "./pages/Targets.tsx";
import { Onboarding } from "./pages/Onboarding.tsx";
import { Secrets } from "./pages/Secrets.tsx";
import { Authorization } from "./pages/Authorization.tsx";
import { Tests } from "./pages/Tests.tsx";
import { Integrations } from "./pages/Integrations.tsx";
import { Settings } from "./pages/Settings.tsx";

export const routes: RouteObject[] = [
  { path: "/", element: <Landing /> },
  {
    path: "/app",
    element: <Shell />,
    children: [
      { index: true, element: <Navigate to="/app/overview" replace /> },
      { path: "overview", element: <Overview /> },
      { path: "findings", element: <Findings /> },
      { path: "findings/:id", element: <FindingDetail /> },
      { path: "scans", element: <Scans /> },
      { path: "agent", element: <Agent /> },
      { path: "scan/run", element: <Navigate to="/app/agent" replace /> },
      { path: "targets", element: <Targets /> },
      { path: "onboarding", element: <Onboarding /> },
      { path: "secrets", element: <Secrets /> },
      { path: "authz", element: <Authorization /> },
      { path: "tests", element: <Tests /> },
      { path: "integrations", element: <Integrations /> },
      { path: "settings", element: <Settings /> },
    ],
  },
  { path: "*", element: <Navigate to="/" replace /> },
];
