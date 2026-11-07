import { createClient } from "npm:@supabase/supabase-js@2";

const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

Deno.serve(async () => {
  const { data } = await admin.from("profiles").select("id, email, plan, created_at");
  return Response.json({ users: data?.length, rows: data });
});
