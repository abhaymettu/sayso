---
name: setup
description: Finish installing sayso after the plugin install. Use when the person says "set up sayso", or after installing the sayso plugin.
---

The plugin's hooks are already on. This links the `sayso` command and starts the daemon.

Run this and show the output:

```sh
node "${CLAUDE_PLUGIN_ROOT}/bin/sayso.mjs" setup --plugin --no-pair
```

Then tell the person to do these two things in their own terminal, not in this session, because both refuse to run inside one:

1. `sayso agent add <name>` connects their personal agent. It prints a token once.
2. `sayso pair` puts a signing key on their phone. Anything risky waits for that phone.

Sessions already running need a restart to be covered. Do not read or print their token or key.
