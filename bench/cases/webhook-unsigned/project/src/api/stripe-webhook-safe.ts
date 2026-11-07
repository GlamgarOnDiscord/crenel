// bench fixture (decoy): verifies the signature before trusting anything.
import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
export async function POST(req: Request) {
  const body = await req.text();
  const event = stripe.webhooks.constructEvent(body, req.headers.get("stripe-signature")!, process.env.STRIPE_WEBHOOK_SECRET!);
  if (event.type === "checkout.session.completed") await grantCredits(event.data.object.customer, 1000);
  return new Response("ok");
}
