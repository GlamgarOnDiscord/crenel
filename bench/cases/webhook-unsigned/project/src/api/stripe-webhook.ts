// bench fixture: trusts the payload without checking Stripe's signature.
export async function POST(req: Request) {
  const event = await req.json();
  if (event.type === "checkout.session.completed") {
    await grantCredits(event.data.object.customer, 1000);
  }
  return new Response("ok");
}
