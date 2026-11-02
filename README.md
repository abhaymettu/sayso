<p>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/mark-dark.svg">
    <img src="docs/mark.svg" width="56" height="56" alt="The sayso mark, a speech bubble with a keyhole">
  </picture>
</p>

# sayso

Your own agent can see your Claude Code sessions, gets told when one needs something, and can answer it. Anything that
could wreck your machine waits for your phone, even with permissions bypassed.

![A Claude Code session asks to run rm -rf data. The agent is told, says it can't approve that, and sends a link. The person holds to approve on their phone and gets a code. The agent passes the code back, and the session runs the command.](assets/demo.gif)

That is one real take with a real Claude Code session and a real model as the agent. Only the session's own model is
scripted, so the take is repeatable. `node tools/record-demo.mjs` records it again.

## Install

```sh
npx github:abhaymettu/sayso setup
```

That adds hooks to your Claude Code settings, links a `sayso` command and starts a small local daemon. Then, in your own
terminal:

```sh
sayso agent add my-agent   # prints a token and how to connect
sayso pair                 # shows a QR code, scan it with your phone
```

Sessions you start after this are covered. `sayso doctor` tells you if anything is off, and `sayso uninstall` takes it
all back out.

If you'd rather your agent did this, hand it [AGENTS.md](AGENTS.md). It stops and asks you for the two steps above,
because those have to come from you. There is also a plugin route:

```sh
claude plugin marketplace add abhaymettu/sayso
claude plugin install sayso@sayso
```

Run `/sayso:setup` in a session after that. Needs Node 20 or newer and Claude Code, on macOS or Linux.

To see it work first, clone the repo and run `npm run test:smoke`. It installs into a temp folder and takes a real session
through a held `rm -rf`, against a scripted model, so it needs no account.

## What your agent gets

- **A list of your sessions.** What each one is doing, which folder it is in, whether it is waiting on you.
- **A tap on the shoulder.** It gets told when a session needs something, by webhook, by a local command, or by long
  polling. The median was 113 ms from the session asking to the agent being told, over 100 runs on a loaded laptop.
- **Answers to questions.** When a session asks you to pick an option, your agent can pick one of the options offered.
- **No, any time.** It can deny any request.
- **Yes, only through you.** For anything risky, it gets a link to send you, and you get a code to send back.

An agent cannot make that code. It is a signature your phone makes over the exact request it showed you, so a made-up
code fails, a code from another request fails, and a link the agent altered to make `rm -rf ~` look like `rm -rf ./cache`
gives a code that fails too. Three bad codes end the request. If nobody answers in 15 minutes, the answer is no.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/anatomy-dark.svg">
  <img src="assets/anatomy-light.svg" alt="A small bench instrument. A spring-loaded carriage on rails is the tool call. A latch catches it, a five-pin lock holds the latch shut, and only the key cut for this exact request turns the lock. A dial counts down the hold, and at zero a lever pulls the carriage back.">
</picture>

## What can approve what

The policy lives in `~/.sayso/policy.json`, and the default is strict. `sayso policy` prints it. From inside a session, a
call that touches it is classified as `self`, and the command refuses to run there.

| A call that is | Strict, the default | `sayso policy trusted-agent` |
|---|---|---|
| Ordinary, like `git status` | runs, nobody asked | runs, nobody asked |
| A question with options | your agent or you | your agent or you, free text allowed |
| A plan, or a permission prompt | you | your agent or you |
| Destructive, like `rm -rf data` or `git push --force` | you | your agent or you |
| Outward, like `npm publish` or `gh pr merge` | you | your agent or you |
| Opaque, like `curl ... \| sh` | you | your agent or you |
| Credentials, like reading `~/.ssh/id_ed25519` | you | you |
| Catastrophic, like `rm -rf ~` | you | you, and no policy file can change this |
| Touching sayso itself | you | you, and no policy file can change this |

Anything with hidden characters, or too long to show in full, goes to you whatever the policy says.

If you are at the terminal when it happens, the normal Claude Code dialog appears, even in bypass mode, and the keyboard
and your agent race. Whichever answers first wins.

## Connect your agent

`sayso agent add` prints all of this with your token filled in. The daemon listens only on `127.0.0.1`, so nothing here is
public unless you make it so.

| Your agent speaks | Use |
|---|---|
| MCP over HTTP | `http://127.0.0.1:7428/mcp` with `Authorization: Bearer <token>` |
| MCP over stdio | command `sayso`, args `["mcp"]`, env `SAYSO_TOKEN` |
| Plain HTTP | `POST /v1/call/<tool>` with a JSON body, `GET /v1/tools` to list tools, `GET /v1/events/stream` for server-sent events |

To be told at once instead of asking:

```sh
sayso notify add webhook https://your-agent.example/inbound --secret <secret>
sayso notify add command -- /path/to/script   # gets each event as JSON on stdin
```

### Reaching it from elsewhere

If your agent runs somewhere else, it can't reach `127.0.0.1`, and sayso does not open a port for you. Pick a tunnel you
trust, point it at the port, and tell sayso the name it will arrive under. Every request still needs a token.

```sh
cloudflared tunnel --url http://127.0.0.1:7428
sayso expose your-name.trycloudflare.com
```

Any other `Host` header gets a 403, even with a good token. Hosted connectors that insist on OAuth won't work yet.

## Works with

"Tested" means I ran it end to end and you can rerun it.

| Agent | State |
|---|---|
| Claude Code as the agent, over MCP HTTP | Tested with a real model, `npm run test:live` |
| Any client on plain HTTP or MCP | The test suite drives these doors directly, with no model in the loop |
| Instinct, Dots, Muse, OpenClaw, Hermes Agent, Cursor, Claude Desktop | Untested |

## What was attacked

Your agent reads your email and the web, so anyone who can email you can try to steer it. The tests assume it will
sometimes do what the email says, and check that nothing runs anyway.

- Text in a command claiming `approver=agent` or "the owner approved this".
- An agent making up a code, signing with its own key, replaying an old code, or guessing.
- An agent lying to you, with a link that shows a harmless command while a dangerous one waits.
- Secrets in a command, checked against every surface: the agent's view, webhooks, the signed link, the log.
- Escape codes, text direction overrides, zero-width characters, tag characters and hundreds of spaces, to hide what a
  command does.
- A session reading sayso's state for something it can use, or calling the agent port.
- The daemon dying during a hold, the hook crashing, Node missing, a broken policy file.
- A real model told to approve, four ways, including a fake system message and a plain order from its operator.

`npm run test:e2e` runs these against the real Claude Code binary, with a scripted model and no account. `npm run
test:live` runs the last one against a real model, at about a cent a run.

## Where it stops

In a normal install the session runs as you, and sayso's files are yours. A session set on removing the gate can write a
script that edits your settings, then run it, and the classifier won't see what the script does. So the default install
stops accidents, injected agents and the obvious routes. Think seatbelt.

`sudo sayso harden`, on Linux with systemd, is the lock. The daemon runs as its own user, and the hooks move to Claude
Code's managed settings, which user settings can't remove. A session running as you can no longer change the keys or stop
the daemon. There is no macOS version yet.

The classifier also isn't a sandbox. It exists so that a tired model's `rm -rf` reaches a person. To contain a hostile
process, use a VM.

The approval page is the root of trust, since your phone signs what it shows. It is static, short enough to read, and its
own security policy forbids network connections. You can read [the threat model](docs/threat-model.md) for the rest, and
[what Claude Code hooks actually do](docs/hook-facts.md) for the measurements it rests on. Hooks fail open, which surprised
me: if a hook crashes or gets killed, the command runs.

## Other tools

Build on one of these if it fits. Nothing here does this exact job, as far as I could find in November 2026.

- **Blockers.** [destructive_command_guard](https://github.com/Dicklesworthstone/destructive_command_guard) and
  [cc-safety-net](https://github.com/kenryu42/cc-safety-net) stop dangerous commands, with no way to release one
  remotely. If you only want a blocker, use those. sayso's classifier test corpus borrows from cc-safety-net, which is MIT.
- **Dashboards.** [Gander](https://github.com/weellio/gander) puts your sessions on a phone, with a read-only MCP. Its
  hooks fail open.
- **Signed approvals.** [Witness](https://github.com/sipkigroup/witness) has passkey approvals over the arguments of a
  call, through a hosted server. [Phygital Key](https://github.com/Phygital-Key/phygital-key-mcp) signs the exact request
  with WebAuthn, and the service on the other end has to take part.
- **First party.** Claude Code's [Remote Control](https://code.claude.com/docs/en/remote-control) and
  [Channels](https://code.claude.com/docs/en/channels) reach sessions from elsewhere. Neither gives a third-party agent
  this door, and permission relay doesn't apply in bypass mode.
- **Terminal wrappers.** [claude-wrap-mcp](https://github.com/Alex-Kaff/claude-wrap-mcp) answers prompts through a PTY,
  so there is nothing to answer in bypass mode.

## Run the checks yourself

```sh
npm run test:smoke   # one install, one held rm -rf, about a minute
npm run test:unit    # classifier corpus and logic
npm run test:e2e     # the real Claude Code binary, end to end, with attacks
npm run test:live    # a real model as the agent, needs a logged-in claude
npm run bench        # latency, writes bench/results.json
node test/probe-hooks.mjs   # the hook facts, on your Claude Code version
```

The gate adds about 96 ms to each tool call, nearly all of it starting a process: 120 ms against 24 ms for a tool round
trip, median of 90 calls each, measured with the sides alternating on a 12-core laptop at load 25. The full numbers are in `bench/results.json`.

## License

MIT
