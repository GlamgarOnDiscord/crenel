/* Provider logos for the custom-model connectors, from @lobehub/icons-static-svg
   (MIT, pinned in package.json). Only the files imported below are bundled.
   They are build-time SVG strings from a pinned package, never user input,
   which is what makes inlining them safe; inlining (rather than <img>) lets
   the single-colour marks take the text colour (currentColor) on the dark UI.
   Coloured variants are used where the pack has one. */
import openai from "@lobehub/icons-static-svg/icons/openai.svg?raw";
import claude from "@lobehub/icons-static-svg/icons/claude-color.svg?raw";
import openrouter from "@lobehub/icons-static-svg/icons/openrouter.svg?raw";
import groq from "@lobehub/icons-static-svg/icons/groq.svg?raw";
import deepseek from "@lobehub/icons-static-svg/icons/deepseek-color.svg?raw";
import mistral from "@lobehub/icons-static-svg/icons/mistral-color.svg?raw";
import gemini from "@lobehub/icons-static-svg/icons/gemini-color.svg?raw";
import xai from "@lobehub/icons-static-svg/icons/xai.svg?raw";
import together from "@lobehub/icons-static-svg/icons/together-color.svg?raw";
import fireworks from "@lobehub/icons-static-svg/icons/fireworks-color.svg?raw";
import ollama from "@lobehub/icons-static-svg/icons/ollama.svg?raw";
import lmstudio from "@lobehub/icons-static-svg/icons/lmstudio.svg?raw";
import vllm from "@lobehub/icons-static-svg/icons/vllm-color.svg?raw";

// Drop the pack's fixed 1em size and <title> (the button carries the name).
const clean = (svg: string) => svg.replace(/\s(width|height)="[^"]*"/g, "").replace(/<title>.*?<\/title>/, "");

const ICONS: Record<string, string> = Object.fromEntries(Object.entries({
  openai, anthropic: claude, openrouter, groq, deepseek, mistral, gemini, xai, together, fireworks, ollama, lmstudio, vllm,
}).map(([k, v]) => [k, clean(v)]));

export const hasProviderIcon = (id: string | undefined) => !!id && Object.prototype.hasOwnProperty.call(ICONS, id);

export function ProviderIcon({ id, size = 16 }: { id: string; size?: number }) {
  const svg = ICONS[id];
  if (!svg) return null;
  return <span className="pico" style={{ width: size, height: size }} aria-hidden="true" dangerouslySetInnerHTML={{ __html: svg }} />;
}
