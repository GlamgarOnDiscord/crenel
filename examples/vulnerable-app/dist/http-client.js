const https = require("https");
// DEMO ONLY: disabled TLS verification so the tls-verification check has a finding.
const agent = new https.Agent({ rejectUnauthorized: false });
