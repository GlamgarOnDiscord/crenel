# Roadmap

Not done yet, in rough order:

- **Authorization**: add the routes `live-bundle` and `review-bundle` list to the matrix automatically (today they are suggested); replay GraphQL global ids leaked in responses; an admin role with an expected "allow"; old and new objects per resource in generated tests. Action-level BOLA (update or delete someone else's object) stays off by default: later, only with declared test accounts, a throwaway object Crenel creates, and a separate opt-in.
- **Secrets**: rotation paths per provider; liveness for AWS (needs a signed request) and Google keys.
- **BaaS**: anonymous writes on Supabase (a separate opt-in, on a throwaway row Crenel creates), Firestore rules (needs a POST, never sent today).
- **Dependencies**: maintainer and publisher changes between versions (needs a history the registry does not expose directly).
- **Agent harness** (research backlog P1+): repetition detector, context editing and file memory, plan/execute split with hypothesis forcing, multi-run voting as a precision filter, an eval harness with pass^k; a model judge wired into the gate (the interface exists, it can only harden).
- **Toolbox** (first phase done: nuclei, katana, trufflehog, httpx in a container whose only exit is the scoped egress proxy, or from a WSL distro on Windows with weaker confinement, see [TOOLBOX.md](TOOLBOX.md)). Next for WSL: a first run on a real Windows machine. Next: test the Docker Desktop path on macOS and Windows; more nuclei results mapped to validators (exposed `.git/config`, `.env`, debug endpoints re-read with a fixed GET); katana routes imported straight into the matrix with an explicit confirmation; trufflehog liveness through a Crenel validator (read-only provider call per detector) instead of trufflehog's own verification; optionally a decrypting proxy so read-only methods are enforced over HTTPS too.
- Repo-relative finding paths, so generated tests resolve from the repo root.
