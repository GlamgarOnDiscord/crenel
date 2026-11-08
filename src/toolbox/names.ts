// The toolbox allowlist. Nothing outside this list can run, on any backend.
export const TOOL_NAMES = ["nuclei", "katana", "trufflehog", "httpx"] as const;
export type ToolName = (typeof TOOL_NAMES)[number];
export const BACKENDS = ["docker", "wsl"] as const;
export type BackendName = (typeof BACKENDS)[number];
