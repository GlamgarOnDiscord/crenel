// bench fixture: fetches whatever URL the caller sends (SSRF).
export async function GET(req: Request) {
  const target = new URL(req.url).searchParams.get("url")!;
  const page = await fetch(target);
  return new Response(await page.text());
}
