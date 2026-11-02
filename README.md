<p>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/mark-dark.svg">
    <img src="docs/mark.svg" width="56" height="56" alt="The sayso mark, a speech bubble with a keyhole">
  </picture>
</p>

# sayso

Your own agent can see your Claude Code sessions, gets told when one needs something, and can answer its questions.
Commands that look destructive, like `rm -rf` or `git push --force`, wait for a yes signed on your phone, even with
permissions bypassed. That catches a tired model's mistakes and an injected agent's yes. It won't stop a session working to
get around it, and [here is where it stops](#where-it-stops).

![A Claude Code session asks to run rm -rf data. The agent is told, says it can't approve that, and sends a link. The person holds to approve on their phone and gets a code. The agent passes the code back, and the session runs the command.](assets/demo.gif)

That is one real take with a real Claude Code session and a real model as the agent. The session's model and the person's
taps are scripted, in a phone-sized browser, so the take is repeatable. `npm run demo` records it again.

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

Run `/sayso:setup` in a session after that. Needs Node 22.14 or newer and Claude Code, on macOS or Linux. The plugin looks for
Node in the usual install locations rather than your `PATH`, and if it can't find it, every call blocks and says why.

To see it work first, clone the repo and run `npm run test:smoke`. It installs into a temp folder and takes a real session
through a held `rm -rf`, against a scripted model, so it needs no account. It proves the gate and the signature check on
one command. It doesn't touch your phone.

## What your agent gets

- **A list of your sessions.** The state of each one, which folder it is in, whether it is waiting on you.
- **A tap on the shoulder.** It gets told when a session needs something, by webhook, by a local command, or by long
  polling. The median was 80 to 85 ms to a webhook on the same machine, over three runs of 100 headless sessions. Your agent's own reaction
  takes as long as its model does.
- **Answers to questions.** When a session asks you to pick an option, your agent can pick one of the options offered.
- **No, any time.** It can deny any request.
- **Yes, only through you.** For anything risky, it gets a link to send you, and you get a code to send back.

An agent that can only reach sayso's tools can't make that code. It is a signature your phone makes over the exact request
it showed you, so a made-up code fails, a code from another request fails, and a link the agent altered to make `rm -rf ~`
look like `rm -rf ./cache` gives a code that fails too. Three bad codes end the request. If nobody answers in 15 minutes, the
answer is no.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/anatomy-dark.svg">
  <img src="assets/anatomy-light.svg" alt="A small bench instrument. A spring-loaded carriage on rails is the tool call. A latch catches it, a five-pin lock holds the latch shut, and only the key cut for this exact request turns the lock. A dial counts down the hold, and at zero a lever pulls the carriage back.">
</picture>

The same idea as a bench instrument. The carriage is the tool call, the latch is the gate, and the lock only turns for the
key cut for this exact request. Your agent carries the key and can't cut one. The dial is the hold, and at zero a lever
pulls the carriage back. [Watch it run](assets/anatomy-dark.mp4), with the dial time-lapsed. Only calls the classifier flags
reach the latch, and in a default install the session can reach the bench too.

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
| Catastrophic, like `dd of=/dev/disk0` | you | you, and no policy file can change this |
| Touching sayso itself | you | you, and no policy file can change this |

Any flagged call with hidden characters, a part hidden as a possible secret, something the classifier couldn't finish
reading, or too much to show in full goes to you whatever the policy says. If part of it is hidden or cut, your phone won't
offer a hold at all, because it would be signing text it never showed you. Answer that one at the terminal, or run it again
without the literal, as with `git push --force https://user:pass@host`. On a long command, the hold unlocks once the end of
it has been on your screen.

An MCP tool whose name says it runs or writes things is held by name, and its arguments are read like a command. If you
trust one, add it to the policy, as in `"trust_tools": ["mcp__myserver__run_*"]`. That drops the hold on the name only, and a
dangerous argument still gets held. A rule has to spell out the server's whole name. Wider ones are ignored, and `sayso doctor`
says so.

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

Any other `Host` header gets a 403, even with a good token, and `npm run test:tunnel` checks this recipe against a real
tunnel. Hosted connectors that insist on OAuth won't work yet.

## What I tried it with

"Tested" means I ran it end to end and you can rerun it. On the session side, sayso covers terminal sessions, `claude -p`,
and sessions hosted through the Agent SDK (`npm run test:sdk`), with the limits under [Where it stops](#where-it-stops).

| Agent | State |
|---|---|
| Claude Code as the agent, over MCP HTTP | Tested with a real model, `npm run test:live`. Told by a notify event, it fetches the link and relays it, then carries your code back. The code in that test comes from a test key, not a phone. |
| A person's page in a phone-sized browser | Tested in Chromium, WebKit and Firefox under Playwright, `test/page/verify-page.mjs`. Not on a real iPhone yet. |
| Any client on plain HTTP or MCP, stdio included | The test suite drives these doors directly, with no model in the loop |
| Instinct, Dots, Muse, OpenClaw, Hermes Agent, Cursor, Claude Desktop | Not tried. Anything that can add an MCP server or make an HTTP call should connect, but I haven't checked that each one lets you. |

## What was attacked

Your agent reads your email and the web, so anyone who can email you can try to steer it. The tests assume it will
sometimes do what the email says, and check that a flagged call stays held anyway. It can still pick an option a session
offered, or say no.

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
test:live` runs the last one against a real model.

## Where it stops

The gate holds only what the classifier recognises. These run with no hold, in any install: `rm -f` on a file, `git rm`,
`unlink`, `mv`, `sed -i`, a write over an existing file, a script written and then run, a plain `git push`. Holding those would hold most of
a normal day. The classifier exists so that a tired model's `rm -rf` reaches a person. It isn't a sandbox, and to contain a
hostile process you want a VM. [The threat model](docs/threat-model.md) lists what else it misses.

In a normal install the session runs as you, and sayso's files are yours. A session set on removing the gate can write a
script that edits your settings, then run it. So the default install catches common accidents, injected agents and the
obvious routes. Think seatbelt.

It also covers only the sessions it is installed for. A session under another `CLAUDE_CONFIG_DIR` has no gate. Neither does
one you start with `--bare`, `--safe-mode`, `--setting-sources` without `user`, `CLAUDE_CODE_SIMPLE` or
`CLAUDE_CODE_SAFE_MODE`, or an Agent SDK host with `settingSources: []`, since those skip user hooks. Claude Code's docs say
`--bare` will become the default for `-p`, which would take `claude -p` out of a default install.

A repository's own settings can switch a default install off too, and no code of mine runs to stop that. They can set
`disableAllHooks`, set `enabledPlugins` to false on the plugin route, name a library with a loader variable like `LD_PRELOAD`,
or add hooks of their own. Their `env` also reaches the commands a session runs, so `BASH_ENV` can run a repository's code
inside a call the gate rightly passed. Treat running `claude` in a folder as trusting its settings. `sayso doctor`, run there
first, warns about all of this.

`sudo sayso harden`, on Linux with systemd, locks the gate in place. The daemon runs as its own user, and the hooks move to
Claude Code's managed settings, which user settings can't remove. A session running as you can no longer change the keys,
reach the owner's socket or stop the daemon, and `--bare`, `--safe-mode`, `disableAllHooks` and a project's settings don't
skip the hooks. It also blanks the loader and shell variables in managed `env`, so a session's zsh stops reading the startup
files in your home. `PATH` and `NODE_OPTIONS` still reach what a session runs, and a repository's own hooks still run, as you.
`sayso status` and `sayso deny` need `sudo` there. `test/harden.mjs` attacks all of that on a throwaway box. It doesn't change
what the classifier recognises, and there is no macOS version yet.

The approval page is the root of trust, since your phone signs what it shows. It is static, short enough to read, and its
own security policy forbids network connections. The hosted copy shares its origin with the other Pages sites on my GitHub
account, so to trust less, serve `docs/` yourself and run `sayso pair --page https://your-host/`. The key on your phone is a
stored one, approving takes a hold and no biometric, and pairing makes it on your computer. A passkey would be stronger, and
some of the tools below use one.

Claude Code's hooks fail open by default: if one crashes or gets killed, the command runs. sayso sets `onFailure: "block"`,
gives the gate clocks of its own, and wraps it so that a failure blocks instead. I tested that on Claude Code 2.1.303, and on
an older version a hook timeout or a killed wrapper may still let the tool run. `sayso doctor` warns about those.
[What Claude Code hooks actually do](docs/hook-facts.md) has the measurements.

## Other tools

I couldn't find one tool that does all of this, as of November 2026: any session you started the normal way, a hold in
bypass mode, a third-party agent answering over MCP or HTTP, and your signature checked locally. Pieces exist, and one of
these may be all you need.

- **Your agent as supervisor.** [PearClaw](https://github.com/sideEyeLabs/pearclaw) lets an OpenClaw agent approve or block
  calls through a hook. No tier only you can release, and it fails open by default.
  [claude-wrap-mcp](https://github.com/Alex-Kaff/claude-wrap-mcp) answers prompts through a PTY, so there is nothing to
  answer in bypass mode.
- **You on your phone.** [Gander](https://github.com/weellio/gander) shows every session and holds destructive commands in
  bypass until you allow them. Its MCP is read-only, so your agent can't answer.
- **Passkeys.** [Interlock](https://github.com/Meraj-08/interlock), [Witness](https://github.com/sipkigroup/witness) and
  [Phygital Key](https://github.com/Phygital-Key/phygital-key-mcp) bind a passkey to the exact request, which is stronger than
  sayso's stored key. None gives your agent a way in. Witness decides through a hosted server, and Phygital Key relies on
  the agent choosing to ask.
- **Blockers.** [destructive_command_guard](https://github.com/Dicklesworthstone/destructive_command_guard) and
  [cc-safety-net](https://github.com/kenryu42/cc-safety-net) stop dangerous commands, with no way to release one remotely. If
  you only want a blocker, use those. sayso's classifier test corpus borrows from cc-safety-net, which is
  [MIT](test/corpus/THIRD-PARTY.md).
- **First party.** `claude agents --json` lists your sessions for free. [Remote Control](https://code.claude.com/docs/en/remote-control)
  is you in Anthropic's apps. [Channels](https://code.claude.com/docs/en/channels-reference) lets a server answer prompts on
  sessions started with it, and `--permission-prompt-tool` hands prompts to an MCP tool in runs started with that flag. In
  bypass mode there is no prompt for either to relay.

## Run the checks yourself

```sh
npm run test:smoke   # one install, one held rm -rf, a few seconds
npm run test:unit    # classifier corpus and logic
npm run test:e2e     # the real Claude Code binary, end to end, with attacks
npm run test:sdk     # a session hosted through the Agent SDK
npm run test:live    # a real model as the agent, needs a logged-in claude, under a cent a run on Haiku
npm run bench        # latency, writes bench/results.json
node test/probe-hooks.mjs   # the hook facts, on your Claude Code version
npx -y -p playwright@1.64.1 node test/page/verify-page.mjs   # the approval page in three browsers
```

The gate adds 76 to 80 ms to each tool call, 47 ms of it starting Node: 93 to 98 ms against 18 ms for a `Bash true` round trip, median of 270 calls a side in each of three runs, with the sides alternating, on a 12-core laptop at load 7 to 8. The three runs are in [`bench/runs/`](bench/runs/).

The classifier flags 1.931 percent of the 194,449 Bash commands in my own Claude Code transcripts, in 23 microseconds at the median. `node tools/measure-classifier.mjs --dir <folder>` prints the same counts for yours, and only counts. Those holds are the price of the gate, so that is the number I watched as the rules grew.

## License

MIT
