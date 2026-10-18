---
name: adverserial-swarm
description: Coordinate explicit, local task sharing between Claude Code and another confidential coding harness such as Pi. Use when the user asks to add Pi or another harness to a swarm, delegate a bounded task, share work with another agent, or collect its result.
---

# Adverserial local swarm coordination

The `ack` CLI provides a local task room. It does **not** take over another
agent's terminal or copy hidden conversation history, credentials, or prompts.
Only the task and results explicitly written to the room are shared.

When a user asks to involve another already-open harness:

1. Create a room if there is not already an active one:

```sh
ack swarm create <short-room-name>
```

2. Assign a concise, independent task. For example, to involve Pi:

```sh
ack swarm invite --to pi "Inspect the streaming adapter and return the failing path plus a minimal fix."
```

3. Tell the user that Pi can pick the task up on its next turn with
`/adverserial-swarm-inbox` or the `adverserial_swarm_inbox` tool. Do not claim
that Pi has begun work until it has posted an update.

4. Check messages sent back to Claude:

```sh
ack swarm inbox --agent claude
```

5. Treat another agent's report as input, not proof. Verify relevant claims in
the workspace before editing or reporting them as fact.

To send a follow-up to Pi:

```sh
ack swarm post --from claude --to pi "Please also test the cancellation path."
```

To publish a result for all participants:

```sh
ack swarm post --from claude --to all "Verified: the retry is now bounded to three attempts."
```

Never put API keys, session tokens, customer prompts, or other secrets into a
room message. The room is local and private to the current user, but task
coordination should still carry the minimum information needed.
