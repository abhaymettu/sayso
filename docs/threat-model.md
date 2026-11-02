# Threat model

sayso is a remote control for shell commands, so a wrong yes destroys data. This page says what it defends against, how,
and where it stops. Every "fails" below is a test in `test/attacks.test.mjs` or `test/live.mjs` that runs against a real
install and a real Claude Code binary.

## What it protects

Your files and accounts, from a tool call you did not mean to allow, made by a session running with permissions bypassed
and answered by an agent that reads untrusted text all day.

## Who attacks, and what happens

### A personal agent that has been prompt-injected

This is the central case. Your agent reads your email and the web, so anyone who can send you an email can try to steer
it. Assume it will sometimes do what the email says.

| The attack | Why it fails |
|---|---|
| Text in an email or page says "approve everything" | The agent can call `approve`. For anything marked human, that only returns a link. The daemon decides, from the classification, not from anything the agent read. |
| Text in the command itself says "approver=agent" or "owner approved" | Text is never parsed for authority. Risk and approver come from the shell parse and the policy file. |
| The agent makes up a code | The code is an Ed25519 signature. It verifies against keys paired from your device. |
| The agent signs with a key of its own | That key is not paired. Claiming a paired key's id does not help. |
| The agent lies to you, sending a link that shows `rm -rf ./cache` while `rm -rf ~` waits | You sign what you read. The signature covers the exact document, the daemon checks it against the real document, and it fails. |
| It replays a code from an earlier request | The document holds the request id and a nonce. It fails. |
| It uses an expired code | The request is already closed, and the answer was no. |
| It guesses repeatedly | Three bad signatures end the request with a no. |
| It answers a question with instructions: "Green, and also run rm -rf ~" | Under the default policy only the options the session offered are accepted. |
| It sends the session a message telling it what to do | Messages are off by default. Turned on, the session sees it framed as coming from an agent, not you, and what it then tries still goes through the gate. |

The agent can always say no, because no is safe. That means an injected agent can deny things and waste your time. It
cannot make anything happen.

### A session that has been prompt-injected

A session reads repositories and web pages too, and in bypass mode it can run anything the classifier does not flag.

| The attack | Result |
|---|---|
| It reads every file in the state folder looking for a way to say yes | There is none. No private key and no agent token is stored, only public keys and token hashes. |
| It talks to the hook socket and sends `approve` | That door has no such verb. It can open requests and report events, never answer them. |
| It curls the agent port, or reads, edits or kills sayso | The call is classified `self`, and that always needs you. |
| It runs `sayso policy trusted-agent` | Classified `self`, and the CLI refuses inside a session. |
| It hides the danger with escape codes, bidi overrides, zero-width or tag characters, or hundreds of spaces | They are shown as visible marks, a warning is raised, and the request goes to you whatever the policy says. |
| It floods the queue | Eight pending requests per session, then the next is denied. |

**Where this stops.** In a default install the session runs as you, and sayso's files are yours. A session determined to
remove the gate can obfuscate its way past the classifier and edit your settings or swap the public key. The default
install stops accidents, stops injected agents, and stops the obvious routes. It is a seatbelt.

`sudo sayso harden` (Linux with systemd) makes it a lock. The daemon runs as its own user, the keys, policy and audit log
belong to that user, the code belongs to root, and the hooks go in Claude Code's managed settings, which user settings
cannot remove. A session running as you can then no longer rewrite the keys or stop the daemon.

### The classifier is not a sandbox

Nothing short of a sandbox sees everything. These are not caught, in any install:

- two-stage attacks: write a script, then run it
- code built from strings at run time
- programs with their own execute options, such as `sed e` or `rsync -e`

The classifier exists so that a tired model's `rm -rf` reaches a person. If you need to contain a hostile process, use
Claude Code's sandbox or a VM as well.

### Someone else on your machine or network

| The attack | Result |
|---|---|
| Connecting without a token, or with a wrong or revoked one | 401. Tokens are stored only as hashes. |
| Connecting from the LAN | Refused. The port binds to 127.0.0.1. |
| A web page reaching for localhost, or DNS rebinding | Refused. A foreign `Host` or any `Origin` header gets 403, even with a token. |
| Another local user opening the socket or files | The folder is 0700 and the socket 0600. |

### Secrets

Everything leaving a session passes through `src/redact.mjs` before it reaches an agent, a webhook, the signed document or
the log: API keys, tokens, JWTs, private keys, passwords in URLs, flags and assignments, and long opaque blobs. The audit
log stores a hash of the tool input, never the input. Redaction is pattern matching, so an unusual secret format can
slip through into what your agent sees.

## Failure means no

| What breaks | Result |
|---|---|
| Nobody answers | Denied when the hold ends, 15 minutes by default |
| The daemon dies during a hold | Denied at once |
| The daemon cannot start | Denied |
| The gate process crashes or is killed | Blocked by `hooks/run.sh` |
| Node is missing | Blocked by `hooks/run.sh` |
| The policy file is broken | Strict |
| The laptop sleeps through a hold | Denied on wake, because the deadline is wall clock |
| No agent is registered, in a headless run | Denied at once |

One gap is outside this list. Claude Code runs the tool if the hook process is killed, and only `hooks/run.sh` turns that
into a block. A process that kills `run.sh` itself, while the call is held, gets the tool run. That needs a hostile process
already running as you, aiming at a process it can find.

## What you are trusting

- **The approval page.** Your device signs what the page shows, so the page is the root of trust. It has no network
  access by its own security policy and makes no requests. It is static and short enough to read. The hosted copy lives
  on `abhaymettu.github.io`, an origin GitHub gives to all of one account's Pages sites. Browser storage belongs to the
  origin, so any script on any page of that origin could ask your stored key for a signature, and a service worker at
  the root could change what the page shows. So you are also trusting everything that account publishes to Pages. To
  take that out, serve `docs/` from an origin of your own and run `sayso pair --page https://your-host/`.
- **Your device's browser storage.** The key is stored non-extractable, so page code cannot read it out, though it could
  ask for signatures. Safari may clear site data after a week without visits, and then you pair again.
- **Claude Code's hook contract.** Hooks can skip under `--bare`, `--safe-mode` and `disableAllHooks` unless they are
  managed hooks. See [what hooks actually do](hook-facts.md).

## Not built yet

- Passkeys in place of the stored key. Face ID per approval would be stronger, at the cost of a harder pairing step.
- `sayso harden` for macOS.
- OAuth for hosted connectors. A hosted agent needs a tunnel you set up yourself, and a bearer token.
