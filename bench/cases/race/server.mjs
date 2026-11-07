// Limits under concurrency: a coupon checked then consumed after an await (the
// bug), an invite accepted in one atomic step (a transaction), and a gift card
// that answers 200 to every retry but only credits once (idempotent).
import { json, serve, userOf } from "../../lib/tenant-app.mjs";

export default () => {
  const wallet = { credits: 0, seats: 1 };
  const coupon = { uses: 0, max: 1 };
  const invite = { accepted: 0, max: 1 };
  const gift = { redeemed: false };
  const db = () => new Promise((r) => setTimeout(r, 25)); // a round trip to the database
  const auth = (req, res) => { const u = userOf(req); if (!u) json(res, 401, { error: "auth" }); return u; };
  return serve([
    { pattern: /^\/api\/me$/, handle(req, res) { if (auth(req, res)) json(res, 200, { id: "user_a", wallet }); } },
    // BUG: read the count, await, then write it.
    { method: "POST", pattern: /^\/api\/coupons\/redeem$/, async handle(req, res) {
      if (!auth(req, res)) return;
      const used = coupon.uses; await db();
      if (used >= coupon.max) return json(res, 409, { error: "coupon already used" });
      coupon.uses++; wallet.credits += 50; await db();
      return json(res, 200, { ok: true });
    } },
    // Correct: check and consume in one step (UPDATE ... WHERE accepted < max).
    { method: "POST", pattern: /^\/api\/invites\/accept$/, async handle(req, res) {
      if (!auth(req, res)) return;
      await db();
      if (invite.accepted >= invite.max) return json(res, 409, { error: "invite already accepted" });
      invite.accepted++; wallet.seats++;
      return json(res, 200, { ok: true });
    } },
    // Correct and idempotent: every retry answers 200, only the first one credits.
    { method: "POST", pattern: /^\/api\/gift\/redeem$/, async handle(req, res) {
      if (!auth(req, res)) return;
      await db();
      if (!gift.redeemed) { gift.redeemed = true; wallet.credits += 1000; }
      return json(res, 200, { ok: true });
    } },
  ]);
};
