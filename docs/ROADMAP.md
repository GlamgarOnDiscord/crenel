# Roadmap

Not done yet, in rough order:

- **Authorization**: import routes from an OpenAPI file or the JS bundle to fill the matrix; replay ids leaked in responses (UUIDs, GraphQL global ids); an admin role with an expected "allow"; old and new objects per resource in generated tests. Action-level BOLA (update or delete someone else's object) stays off by default: later, only with declared test accounts, a throwaway object Crenel creates, and a separate opt-in.
- **Secrets**: liveness checks with a read-only provider call (e.g. Stripe `GET /v1/balance`), strictly opt-in with the provider host declared, giving active / revoked / unknown; rotation paths.
- **BaaS**: anonymous writes on Supabase (a separate opt-in, on a throwaway row Crenel creates), Firestore rules (needs a POST, never sent today).
- **Dependencies**: an age and publisher signal against slopsquatting and maintainer takeovers.
- **Agent harness** (research backlog P1+): repetition detector, context editing and file memory, plan/execute split with hypothesis forcing, multi-run voting as a precision filter, an eval harness with pass^k; a model judge wired into the gate (the interface exists, it can only harden).
- **Network containment outside the process**: an optional Docker "toolbox" image (nuclei, trufflehog) whose only network exit is Crenel's scoped proxy, usable on Windows through Docker Desktop. External tools stay out until then: they would bypass the scoped client.
- Repo-relative finding paths, so generated tests resolve from the repo root.
