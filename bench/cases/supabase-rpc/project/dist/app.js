// bench fixture: a client bundle calling Postgres functions. {{BASE}} is the local fake gateway.
const supabase = createClient("{{BASE}}", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImJlbmNocmxzIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjcyMjU2MDAsImV4cCI6MjA4Mjc1ODQwMH0.YW5vbi1iZW5jaC1zaWduYXR1cmUtbm90LXJlYWw");
export const searchMembers = () => supabase.rpc("search_members");
export const myInvoices = () => supabase.rpc("my_invoices");
export const trackView = () => supabase.rpc("track_view");
