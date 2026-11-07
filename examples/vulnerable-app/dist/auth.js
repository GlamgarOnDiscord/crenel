const jwt = require("jsonwebtoken");
// DEMO ONLY: alg none accepts unsigned tokens (auth bypass).
module.exports = (t) => jwt.verify(t, KEY, { algorithms: ["HS256", "none"] });
