export declare const ALLOWED_DIRS: string[];
export declare const ALLOWED_TAGS: string[];
export declare const DENIED_TAGS: string[];
export declare function isAllowedTemplate(text: string, rel: string): { ok: boolean; reason: string };
export declare function pruneTemplates(root: string): { kept: number; removed: number };
