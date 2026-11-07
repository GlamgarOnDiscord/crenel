// Settings page: saves the profile form as is.
export const saveProfile = (form) =>
  fetch("/api/me", { method: "PATCH", body: JSON.stringify({ displayName: form.name, plan: form.plan }) });
