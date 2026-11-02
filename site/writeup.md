# sayso

If you run Claude Code with permissions bypassed, a model that decides on `rm -rf data` just runs it. And your personal agent, the one that reads your email and can text you, has no idea that session exists. sayso connects the two. Your agent can list your sessions, gets told when one needs something, and can answer its questions, while commands that look destructive wait for a yes signed on your phone.

The hard part is that this is a remote control for shell commands, handed to something that reads email. Anyone who can email you can try to steer your agent, so I built it assuming the agent will sometimes do what the email says. When a session wants to run `rm -rf data`, the agent can't approve it. It gets a link to send you, your phone shows the exact request and signs it, and you send the code back through the agent. A made-up code fails, a code from another request fails, and a link the agent altered to make `rm -rf ~` look like `rm -rf ./cache` gives a code that fails too. If nobody answers in 15 minutes, the answer is no.

## What your agent can do

It can see every session you started the normal way, in a terminal, with `claude -p` or through the Agent SDK. It hears about a session that needs something by webhook, by a local command or by long polling, and the median was 80 to 85 ms to a webhook on the same machine. When a session asks you to pick an option, it can pick one of the options offered. It can say no to anything.

For anything risky it can only pass the request along. The policy is strict by default, and a session that tries to change it has to come to you for that too. A loose policy, `trusted-agent`, lets your agent say yes to destructive commands if you want that, but it never covers credentials, a catastrophic command like `dd of=/dev/disk0`, or sayso itself. The floor on those last two is in code, so no policy file can move it.

## How it holds a call

Claude Code runs a hook before every tool call, even in bypass mode. The hook is a small classifier reading the command, and on an ordinary call it adds 76 to 80 ms, 47 ms of that starting Node. A flagged call opens a request with a local daemon and waits. The approval page is a static file with a security policy that forbids network connections, so the request travels inside the link and your signature is checked on your own machine against a key made at pairing.

Most of the design came from measuring what the hooks really do. Claude Code's hooks fail open by default, so a hook that crashes or is killed lets the command run. I measured each failure on the real binary (`node test/probe-hooks.mjs`, Claude Code 2.1.303) and the gate now sets `onFailure: "block"`, has clocks of its own, and blocks when it can't finish reading.

## What did not work

My first top claim was wrong. I wrote that nothing destructive runs without your say-so, and a reviewer read the code and showed that plenty does. `rm -f`, `mv`, `sed -i`, a write over an existing file, a script written and then run, and a plain `git push` all run with no hold. Holding them would hold most of a normal day, and a gate that holds normal work gets uninstalled. It flags 1.931 percent of the Bash commands in my own transcripts (`node tools/measure-classifier.mjs --dir <folder>`), up from 1.626 percent as the rules grew. So the claim now says what it does. It catches a tired model's mistakes and an injected agent's yes, and it won't stop a session working to get around it.

Fresh reviewers attacked it four times with the code in hand, and for three rounds they kept finding routes. The first found 2 critical and 5 high findings, the second 3 and 6, the third 1 and 6. A fourth pass aimed only at the last round's fixes found none, which says those fixes held and doesn't say nothing is left. In the third round, a repository holding only `{"env":{"SHELLOPTS":"noexec"}}` stopped the gate from running at all, because Claude Code started the hook through a shell that reads that variable before the hook's first word. Now the hook starts with no shell in front of it.

Some of this can't be closed from a hook. A repository's settings can still switch a default install off with `disableAllHooks`, or add hooks of their own, and no code of mine runs at that point. `sayso doctor` warns about them, but you should treat running `claude` in a folder as trusting its settings.

In a normal install the session runs as you and sayso's files are yours. A session set on removing the gate can write a script that edits your settings and run it. That makes the default install a seatbelt. `sudo sayso harden`, on Linux with systemd, moves the daemon to its own user and the hooks to managed settings, and `test/harden.mjs` attacks that on a throwaway box. There is no macOS version.

The approval page has not been on a real iPhone. It ran in Chromium, WebKit and Firefox under Playwright, in a phone-sized window. The key on your phone is a stored one made on your computer at pairing, and a passkey would be stronger. Instinct, Dots, Muse, OpenClaw, Hermes Agent, Cursor and Claude Desktop are all untried, and I only list Claude Code with a real model as tested.

## Other tools

I looked for one tool that does all of this and couldn't find it, as of November 2026. PearClaw lets an OpenClaw agent approve calls through a hook, with no tier only you can release. Gander shows every session and holds destructive commands in bypass, but its MCP is read-only. Interlock, Witness and Phygital Key bind a passkey to the exact request, which is stronger than sayso's key, and none gives your agent a way in. If you only want a blocker, destructive_command_guard and cc-safety-net do that with no remote release. The README links each one.

## Run it yourself

`npm run test:smoke` installs into a temp folder and takes a real session through a held `rm -rf` against a scripted model, so it needs no account. `npm run test:e2e` runs the attacks against the real binary. The install is one line, `npx github:abhaymettu/sayso setup`, and `sayso uninstall` takes it back out.
