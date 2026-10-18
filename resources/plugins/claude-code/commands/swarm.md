---
description: Read confidential swarm work shared with this Claude session
---

Read the pending local swarm messages addressed to Claude:

```sh
ack swarm inbox --agent claude
```

If the inbox contains a task, complete it only after checking the workspace and
post a concise verified result for the requested recipient with:

```sh
ack swarm post --from claude --to all "<verified result>"
```

The local swarm room contains only messages deliberately added to it. Never
post API keys, session tokens, or unneeded customer prompt contents.
