// Files joined to a message in the Composer. Only text travels, in its own
// `attachments` field next to the prompt (POST /api/runs): the server reads
// the user's intent from the prompt alone and hands the files to the model as
// untrusted content (src/agent/run.ts). Limits match the server's.

export interface Attachment { name: string; text: string }

/** What the server keeps of a prompt (the user's own text). */
export const PROMPT_MAX = 4000;
/** What the server accepts in attachments (src/server/http.ts), per run. */
export const ATTACH_MAX_FILES = 5;
export const ATTACH_MAX_CHARS = 100_000;

const TEXT_EXT = /\.(txt|md|markdown|json|jsonc|ya?ml|toml|ini|cfg|conf|env|log|csv|tsv|xml|html?|css|scss|less|js|mjs|cjs|jsx|ts|mts|cts|tsx|vue|svelte|py|rb|go|rs|java|kt|php|cs|c|h|cpp|hpp|sh|bash|zsh|sql|graphql|gql|prisma|tf|hcl|dockerfile|gitignore|lock|properties|rules)$/i;
const TEXT_NAMES = /^(dockerfile|makefile|procfile|\.env(\..+)?|\.npmrc|\.gitignore)$/i;

/** Refusal message for a file the console cannot send as text, null when it looks like text. */
export function refuseByType(f: { name: string; type: string }): string | null {
  const t = f.type.toLowerCase();
  if (t.startsWith("image/")) return `${f.name}: les images ne sont pas envoyées, seulement des fichiers texte.`;
  if (t.startsWith("text/") || /json|xml|yaml|javascript|typescript|x-sh|sql|toml/.test(t)) return null;
  if (TEXT_EXT.test(f.name) || TEXT_NAMES.test(f.name)) return null;
  return `${f.name}: fichier binaire ou de type inconnu, seuls les fichiers texte sont envoyés.`;
}

/** True when decoded contents look binary (NUL bytes or many replacement characters). */
export function looksBinary(text: string): boolean {
  if (text.includes("\u0000")) return true;
  const bad = text.split("�").length - 1;
  return text.length > 0 && bad / text.length > 0.01;
}

/** Null when the message and its files fit what the server accepts, else the refusal to show. */
export function tooLong(prompt: string, files: Attachment[], max = PROMPT_MAX): string | null {
  if (prompt.length > max) return `Message trop long: ${prompt.length} caractères, le serveur en garde ${max}. Mettez le reste dans un fichier joint.`;
  if (files.length > ATTACH_MAX_FILES) return `${files.length} fichiers joints, ${ATTACH_MAX_FILES} au plus.`;
  const n = files.reduce((t, f) => t + f.text.length, 0);
  if (n > ATTACH_MAX_CHARS) return `Fichiers joints trop longs: ${n} caractères, ${ATTACH_MAX_CHARS} au plus. Retirez un fichier ou raccourcissez-le.`;
  return null;
}
