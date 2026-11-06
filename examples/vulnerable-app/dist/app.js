// DEMO ONLY. This file intentionally contains fake secrets so `bastion scan`
// has something to find. None of these are real credentials.
const config = {
  // A server-side key that should never be in a client bundle:
  stripeSecret: "sk_live_FAKE0000000000000000demo",
  publishable: "pk_live_this_one_is_fine_to_ship",
  googleMapsKey: "AIzaFAKE_demo_key_000000000000000000000",
};
export default config;
