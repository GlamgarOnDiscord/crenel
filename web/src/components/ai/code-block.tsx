/* Adapted from Vercel AI Elements `code-block.tsx` (Apache-2.0, see NOTICE.txt):
   header with file name, copy action. Syntax highlighting (shiki) removed to
   keep the demo light; the code keeps the mono face. */
import { Check, Copy, FileCode2 } from "lucide-react";
import { useEffect, useState } from "react";
import { useToast } from "../toast";

export function CodeBlock({ code, filename, language }: { code: string; filename?: string; language?: string }) {
  const [copied, setCopied] = useState(false);
  const toast = useToast();
  useEffect(() => { if (!copied) return; const t = setTimeout(() => setCopied(false), 1600); return () => clearTimeout(t); }, [copied]);
  async function copy() {
    try { await navigator.clipboard.writeText(code); } catch { /* clipboard unavailable */ }
    setCopied(true);
    toast({ type: "success", title: "Code copié" });
  }
  return (
    <div className="codeblock" data-language={language}>
      <div className="cb-hd">
        <FileCode2 className="size-3.5" aria-hidden="true" />
        <span className="font-mono">{filename ?? language}</span>
        <span className="sp" />
        <button type="button" className="copybtn icon" onClick={copy} aria-label={copied ? "Copié" : "Copier le code"}>
          <span className="t-iconswap" data-state={copied ? "b" : "a"}>
            <Copy className="ia size-3.5" aria-hidden="true" /><Check className="ib size-3.5" aria-hidden="true" />
          </span>
        </button>
      </div>
      <pre><code>{code}</code></pre>
    </div>
  );
}
