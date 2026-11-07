// DEMO ONLY. A self-hosted Supabase client, as an app built fast would ship it.
// The anon key is public by design (fake here). The demo server in
// examples/vulnerable-app/server.mjs answers on this URL with one table left
// without row-level security, so `crenel serve` can prove it live.
import { createClient } from "@supabase/supabase-js";
export const supabase = createClient("http://127.0.0.1:4580", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRlbW8iLCJyb2xlIjoiYW5vbiIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoyMDAwMDAwMDAwfQ.ZGVtby1zaWduYXR1cmUtbm90LXJlYWw");
