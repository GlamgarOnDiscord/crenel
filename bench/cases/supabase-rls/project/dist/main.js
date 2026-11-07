// bench fixture: a client bundle wired to a Supabase project. {{BASE}} is the local fake PostgREST.
const supabase = createClient("{{BASE}}", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImJlbmNocmxzIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjcyMjU2MDAsImV4cCI6MjA4Mjc1ODQwMH0.YW5vbi1iZW5jaC1zaWduYXR1cmUtbm90LXJlYWw");
export const loadProfile = (id) => supabase.from("profiles").select("*").eq("id", id);
