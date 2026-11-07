// Menu: accessible buttons, and a GET for the current plan.
export const item = (label, onClick) => h("li", { role: "menuitem", tabIndex: 0, onClick }, label);
export const loadPlan = () => fetch("/api/me/plan").then((r) => r.json());
