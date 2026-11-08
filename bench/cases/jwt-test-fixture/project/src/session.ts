import jwt from "jsonwebtoken";

export function readSession(token: string, key: string) {
  // Accepts "none": a token with no signature passes.
  return jwt.verify(token, key, { algorithms: ["HS256", "none"] });
}
