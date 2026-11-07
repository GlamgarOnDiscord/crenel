// Cart page: the browser sums the lines and sends the total with the order.
export async function placeOrder(lines) {
  const total = lines.reduce((s, l) => s + l.qty * l.unitPrice, 0);
  const res = await fetch("/api/orders", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ lines: lines.map((l) => l.sku), total, currency: "eur" }),
  });
  return res.json();
}
