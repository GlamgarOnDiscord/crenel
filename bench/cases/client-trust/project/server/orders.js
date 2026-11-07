// Server: prices come from the catalogue, never from the request.
app.post("/api/orders", async (req, res) => {
  const amount = await priceOf(req.body.lines);
  const intent = await stripe.paymentIntents.create({ amount: amount, currency: "eur" });
  res.json({ clientSecret: intent.client_secret });
});
