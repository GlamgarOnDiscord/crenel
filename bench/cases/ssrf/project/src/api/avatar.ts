// bench fixture (decoy): only fetches from an allowlisted host.
const ALLOWED = new Set(["avatars.githubusercontent.com"]);
export async function GET(req: Request) {
  const target = new URL(new URL(req.url).searchParams.get("src")!);
  if (target.protocol !== "https:" || !ALLOWED.has(target.hostname)) return new Response("refused", { status: 400 });
  const img = await fetch(target);
  return new Response(img.body);
}
