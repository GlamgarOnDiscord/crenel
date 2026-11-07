// bench fixture: a chat widget that calls the model API from the browser, key split in two.
const k = "sk-proj-Qm9vdHN0cmFwS2V5Rm9yQmVuY2gT3BlbkF" + "Jx7Zk2LmN9pQr4StUvWxYz0aBcDeFgHiJkLmNoPqRs";
export const ask = (q) => fetch("https://api.openai.com/v1/chat/completions", { method: "POST", headers: { authorization: "Bearer " + k }, body: JSON.stringify({ model: "gpt-x", messages: [{ role: "user", content: q }] }) });
export const docs = "Set STRIPE_SECRET_KEY=" + "sk_live_" + "xxxxxxxxxxxxxxxxxxxxxxxx" + " in your server env.";
export const greet = (n) => "Hello, " + "friend" + "!";
