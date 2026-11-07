// Upgrade button: the server creates a Checkout Session from a known price id.
export const upgrade = () =>
  fetch("/api/billing/checkout", { method: "POST", body: JSON.stringify({ price: "price_1PproMonthly" }) }).then((r) => r.json()).then((s) => (location.href = s.url));
