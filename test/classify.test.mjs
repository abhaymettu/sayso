import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { closeSync, mkdtempSync, openSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { classifyShell, classifyToolCall, RISK_ORDER } from '../src/classify.mjs';
import { forDisplay, redact } from '../src/redact.mjs';

const CTX = { home: '/Users/dev', cwd: '/Users/dev/project', stateDir: '/Users/dev/.sayso' };

const corpusPath = (name) => new URL(`./corpus/${name}`, import.meta.url);
const decode = (line) => line.replace(/\\\\n|\\n/g, (match) => (match === '\\n' ? '\n' : '\\n'));
const corpusLines = (name) =>
  readFileSync(corpusPath(name), 'utf8')
    .split('\n')
    .filter((line) => line !== '' && !line.startsWith('#'));

const dangerous = corpusLines('dangerous.tsv').map((line) => {
  const tab = line.indexOf('\t');
  return { risk: line.slice(0, tab), source: line.slice(tab + 1) };
});
const safe = corpusLines('safe.txt');

test('corpus keeps its minimum size', () => {
  assert.ok(dangerous.length >= 150, `dangerous has ${dangerous.length}`);
  assert.ok(safe.length >= 150, `safe has ${safe.length}`);
});

for (const { risk, source } of dangerous) {
  test(`flags ${risk}: ${source}`, () => {
    assert.equal(classifyShell(decode(source), CTX)?.risk, risk);
  });
}

for (const source of safe) {
  test(`passes: ${source}`, () => {
    assert.equal(classifyShell(decode(source), CTX), null);
  });
}

// Known costs: a search for the socket's file name flags self because the
// argument names it, and `rg sayso` passes only because a bare word is not a path.
test('known cost: searching for the socket name flags self', () => {
  assert.equal(classifyShell('cat notes/sayso.sock', CTX)?.risk, 'self');
  assert.equal(classifyShell('grep -r sayso.sock src', CTX), null);
  assert.equal(classifyShell('grep -r x sayso.sock', CTX)?.risk, 'self');
});

test('RISK_ORDER runs worst first', () => {
  assert.deepEqual(RISK_ORDER, ['catastrophic', 'self', 'credentials', 'destructive', 'outward', 'opaque']);
});

test('verdict carries the worst risk, every reason and each simple command', () => {
  assert.deepEqual(classifyShell('npm publish; rm -rf /; git reset --hard', CTX), {
    risk: 'catastrophic',
    why: ['recursive delete of a system root', 'git reset --hard', 'npm publish'],
    commands: ['npm publish', 'rm -rf /', 'git reset --hard'],
  });
});

test('reasons never contain command text', () => {
  const { why } = classifyShell('rm -rf /Users/dev/private-client-name; cat ~/.ssh/id_rsa', CTX);
  assert.deepEqual(why, ['reads a secret file', 'recursive delete']);
});

test('over-long commands are opaque even when they look harmless', () => {
  assert.deepEqual(classifyShell(`echo ${'a'.repeat(20001)}`, CTX), { risk: 'opaque', why: ['command is too long to read'], commands: [] });
});

test('absurd nesting fails closed instead of throwing', () => {
  assert.equal(classifyShell('$('.repeat(9000) + ')'.repeat(9000), CTX)?.risk, 'opaque');
});

test('the state directory follows ctx', () => {
  const ctx = { ...CTX, stateDir: '/var/lib/guard' };
  assert.equal(classifyShell('cat /var/lib/guard/token', ctx)?.risk, 'self');
  assert.equal(classifyShell('cat /var/lib/other/token', ctx), null);
});

test('relative paths resolve against ctx.cwd', () => {
  const inHome = { ...CTX, cwd: '/Users/dev' };
  assert.equal(classifyShell('cat .aws/credentials', inHome)?.risk, 'credentials');
  assert.equal(classifyShell('cat .aws/credentials', CTX), null);
  assert.equal(classifyShell('rm -rf ..', inHome)?.risk, 'catastrophic');
});

test('a Claude config dir elsewhere counts through ctx', () => {
  const ctx = { ...CTX, configDir: '/opt/agent-config' };
  assert.equal(classifyShell('echo x > /opt/agent-config/settings.json', ctx)?.risk, 'self');
  assert.equal(classifyShell('echo x > /OPT/agent-config/nested/settings.local.json', ctx)?.risk, 'self');
  assert.equal(classifyShell('echo x > $CLAUDE_CONFIG_DIR/settings.json', ctx)?.risk, 'self');
  assert.equal(classifyShell('echo x > /opt/agent-config/notes.json', ctx), null);
  assert.equal(classifyShell('echo x > /opt/other/settings.json', ctx), null);
  assert.equal(classifyToolCall('Write', { file_path: '/opt/agent-config/settings.json' }, ctx)?.risk, 'self');
});

test('a non-dot state directory still compares as a path', () => {
  const ctx = { ...CTX, stateDir: '/var/lib/guard' };
  assert.equal(classifyShell('cat /VAR/LIB/GUARD/token', ctx)?.risk, 'self');
  assert.equal(classifyShell('cat /var/lib/gua*/token', ctx)?.risk, 'self');
  assert.equal(classifyShell('cat /var/lib/*/token', ctx)?.risk, 'self');
  assert.equal(classifyShell('cat /var/log/*/token', ctx), null);
});

test('more strings than the walk will read fails closed instead of going quiet', () => {
  const words = Array.from({ length: 3000 }, () => '"a b"').join(' ');
  assert.equal(classifyShell(`tool ${words}`, CTX)?.risk, 'opaque');
});

const SIZE = 19990;
const fill = (head, unit, tail = '') => head + unit.repeat(Math.floor((SIZE - head.length - tail.length) / unit.length)) + tail;
const loop64 = (body) => `for i in ${Array.from({ length: 64 }, (_, k) => k).join(' ')}; do ${body}; done`;

const SLOW_COMMANDS = {
  'one word of [': fill('echo ', '['),
  'a tool and one word of [': fill('tool ', '['),
  'brace then dots': fill('echo {', '.'),
  'nested braces': fill('echo ', '{a,'),
  'many brace groups': fill('echo ', '{a,b}'),
  'escaped quotes in a string': `tool '${'\\"'.repeat(9980)}'`,
  'comma then spaces in a string': `tool '"a",${' '.repeat(19970)}x'`,
  'awk prints': `awk '${'print '.repeat(3320)}'`,
  'perl opens': `perl -e '${'open '.repeat(3980)}'`,
  'open parens': fill('', '('),
  'arithmetic nest': `${'$(('.repeat(3300)}1${'))'.repeat(3300)}`,
  'substitution nest': `${'$('.repeat(6600)}x${')'.repeat(6600)}`,
  'many quoted args': fill('tool ', "'a b' "),
  'dash dash tails': fill('tool ', 'a -- '),
  'runner words': fill('tmux ', 'cd '),
  'loop of brackets': loop64(`echo ${'['.repeat(19000)}`),
  'loop of escaped quotes': loop64(`tool '${'\\"'.repeat(9000)}'`),
  'loop in a string': `tool '${loop64(`echo ${'['.repeat(18000)}`)}'`,
  'nested strings': fill('tool ', "'a '\\''b '"),
  'a glob of stars': `cat /Users/dev/.${'*'.repeat(19000)}q`,
  'a glob of star dots': fill('cat /Users/dev/', '*.'),
  'question marks in a delete': fill('rm -rf ', '?'),
  'bracket sets': fill('cat /Users/dev/', '[a'),
  'pkill with a nested pattern': `pkill -f '${'(.*)'.repeat(4900)}x'`,
  'pkill with stars': fill("pkill -f 'a", '.*', "b'"),
  'quote operators': `perl -e '${'q('.repeat(9900)}'`,
  'function definitions': fill('', 'f(){ :; };'),
  'heredocs': fill('', 'cat <<A\n'),
  'empty string pieces': fill('rm ', "''"),
  'one long path': `cat /${'a/'.repeat(9980)}`,
  'dot dot path': fill('cat ', '../'),
  'settings segments': fill('cat ', '.claude/'),
  'assignments': fill('', 'a=$b '),
  'cd chain': fill('', 'cd a;'),
  'an open list in inline code': `python3 -c '${'["a", '.repeat(3300)}'`,
};

/** A fresh process each time, because that is what the hook is. Regexes start in the interpreter there, far slower than a warm loop shows. */
function coldRun(modulePath, exportName, input) {
  const moduleUrl = new URL(modulePath, import.meta.url).href;
  const script = `const input = require('node:fs').readFileSync(0, 'utf8');
    import(${JSON.stringify(moduleUrl)}).then((m) => {
      const start = performance.now();
      const result = m.${exportName}(input, ${JSON.stringify(CTX)});
      console.log(JSON.stringify({ ms: performance.now() - start, result }));
    });`;
  // spawnSync with a large `input` sometimes never finishes on macOS: the child waits on stdin and the parent in its loop,
  // with none of our code involved. Node 26.10, 200 KB, within 200 calls. A file as stdin has no such write to lose.
  const dir = mkdtempSync(join(tmpdir(), 'sayso-cold-'));
  writeFileSync(join(dir, 'input'), input);
  const stdin = openSync(join(dir, 'input'), 'r');
  try {
    const child = spawnSync(process.execPath, ['-e', script], { stdio: [stdin, 'pipe', 'pipe'], encoding: 'utf8' });
    assert.equal(child.status, 0, child.stderr);
    return JSON.parse(child.stdout);
  } finally {
    closeSync(stdin);
    rmSync(dir, { recursive: true });
  }
}

const bestOfTwo = (run) => {
  const first = run();
  const second = run();
  return first.ms <= second.ms ? first : second;
};

for (const [name, command] of Object.entries(SLOW_COMMANDS)) {
  test(`classifies in under 200 ms when cold: ${name}`, () => {
    assert.ok(command.length <= 20000, `input is ${command.length}`);
    const { ms } = bestOfTwo(() => coldRun('../src/classify.mjs', 'classifyShell', command));
    assert.ok(ms < 200, `took ${ms.toFixed(0)} ms`);
  });
}

test('running out of budget keeps what was seen and never goes quiet', () => {
  const strings = "'a b' ".repeat(2100);
  const after = classifyShell(`tool ${strings}; rm -rf victim`, CTX);
  assert.equal(after.risk, 'destructive');
  assert.ok(after.why.includes('too many nested strings to read'), after.why.join());
  assert.equal(classifyShell(`tool ${strings} 'rm -rf victim'`, CTX)?.risk, 'opaque');
  assert.equal(classifyShell(`tool ${'a -- '.repeat(3900)}`, CTX)?.risk, 'opaque');
  assert.equal(classifyShell(`tmux ${'cd '.repeat(70)}git reset --hard`, CTX)?.risk, 'opaque');
});

test('running out of time reads as opaque and keeps what was seen', () => {
  assert.equal(classifyShell('('.repeat(19990), CTX)?.risk, 'opaque');
  const verdict = classifyShell(`rm -rf /; ${'('.repeat(19900)}`, CTX);
  assert.ok(RISK_ORDER.indexOf(verdict.risk) >= RISK_ORDER.indexOf('opaque'), verdict.risk);
});

test('loop iterations and string depth draw on one budget', () => {
  const body = "tool 'a b' 'c d' 'e f' 'g h'";
  const verdict = classifyShell(`tool '${loop64(loop64(body)).replaceAll("'", '"')}'`, CTX);
  assert.ok(verdict === null || verdict.risk === 'opaque', verdict?.risk);
  assert.equal(classifyShell(`tool "${loop64(loop64("tool 'rm -rf victim'"))}"`, CTX)?.risk, 'destructive');
});

const SLOW_TEXT = {
  'token dashes': 'token-'.repeat(200000),
  'mysql words': 'mysql '.repeat(200000),
  'dots': 'a.'.repeat(500000),
  'zip words': 'zip '.repeat(250000),
  'user flags': '-u a '.repeat(200000),
  'password names': 'password='.repeat(100000),
  'cookie pairs': `Cookie: ${'a=1; '.repeat(200000)}`,
  'an open key block': `-----BEGIN PRIVATE KEY-----${'\nabcd'.repeat(200000)}`,
  'many key blocks': '-----BEGIN PRIVATE KEY-----\n'.repeat(40000),
  'percent escapes': '%41'.repeat(300000),
  'percent words': '%41 '.repeat(250000),
  'split quotes': `"a"'b'`.repeat(160000),
  'split quoted words': `"a"'b' `.repeat(140000),
  'invisible marks': '\u200b'.repeat(1000000),
  'long blob': 'a'.repeat(1000000),
  'slashes': 'a/'.repeat(500000),
  'hex': 'f'.repeat(1000000),
  'url colons': 'a://b:'.repeat(160000),
  'at signs': `https://${'a:b@'.repeat(250000)}`,
  'blank lines': '\n'.repeat(1000000),
  'comment lines': '# x\n'.repeat(250000),
  'nested pairs': `a='b="c=`.repeat(100000),
};

for (const [name, text] of Object.entries(SLOW_TEXT)) {
  test(`redacts in under 100 ms when cold: ${name}`, () => {
    const { ms } = bestOfTwo(() => coldRun('../src/redact.mjs', 'redact', text));
    assert.ok(ms < 100, `took ${ms.toFixed(0)} ms`);
  });
}

const key = (prefix, length = 32) => prefix + 'a1B2'.repeat(Math.ceil(length / 4)).slice(0, length);

const SECRET_SHAPES = [
  `OPENAI_KEY=${key('')}`,
  `SIGNING_KEY=${key('')}`,
  `DB_PW=${key('')}`,
  `SMTP_PASS=${key('')}`,
  `AWS_SESSION_TOK="${key('')}"`,
  key('dckr_pat_'),
  key('secret_'),
  key('hvs.'),
  key('glpat-'),
  key('gldt-'),
  key('sbp_'),
  key('pypi-'),
  key('sntrys_'),
  key('tskey-'),
  key('ghp_', 36),
  key('xoxb-'),
  key('sk-ant-'),
  key('AIza', 35),
  `123456789:${key('', 35)}`,
  `M${key('', 23)}.GabcDE.${key('', 27)}`,
  `https://hooks.slack.com/services/${key('T/B/')}`,
  `https://discord.com/api/webhooks/1/${key('')}`,
  `https://x.blob.core.windows.net/c/b?sv=2022&sig=${key('')}`,
  `AccountKey=${key('')}`,
  `-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n${key('')}\n-----END PGP PRIVATE KEY BLOCK-----`,
  `-----BEGIN OPENSSH PRIVATE KEY-----\n${key('')}\n${key('')}\n-----END OPENSSH PRIVATE KEY-----`,
  `postgres://app:${key('')}@db/x`,
  `https://:${key('')}@example.com/x`,
  `curl https://${key('')}:${key('')}@example.com`,
  `sqlcmd -S db -U sa -P ${key('')}`,
  `ldapsearch -D cn=admin -w ${key('')}`,
  `openssl enc -aes-256-cbc -k ${key('')} -in x`,
  `htpasswd -b .htpasswd admin ${key('')}`,
  `smbclient //h/s -U admin%${key('')}`,
  `ssh-keygen -p -P ${key('')} -f k`,
  `curl -b ${key('')} https://x.com`,
  `curl --cookie ${key('')} https://x.com`,
  `echo ${key('')} | docker login -u me --password-stdin`,
  `git -c http.extraHeader='PRIVATE-TOKEN: ${key('')}' pull`,
  `password%3D${key('')}`,
  `sk%2Dant%2D${key('')}`,
  `sk-ant%252D${key('')}`,
  `K="sk-ant-"'${key('')}'`,
  `curl "https://x.com/login?password=${key('')}"`,
  `curl "https://x.com/login?pass%77ord=${key('')}"`,
  `{"pass\\u0077ord":"${key('')}"}`,
  `sk-\u200bant-${key('')}`,
  `{\\"password\\":\\"${key('')}\\"}`,
];

for (const shape of SECRET_SHAPES) {
  test(`hides the secret in: ${shape.slice(0, 48)}`, () => {
    assert.ok(!redact(shape).includes(key('', 16)), redact(shape));
  });
}

const STAYS_VISIBLE = [
  ['TOKEN="$(rm -rf ~/Documents)" ./deploy.sh', 'rm -rf ~/Documents'],
  ['password "$(rm -rf ~/Documents)"', 'rm -rf ~/Documents'],
  ['TOKEN=`rm -rf ~/Documents`', 'rm -rf ~/Documents'],
  ['echo cookie: x; rm -rf ~/Documents', 'rm -rf ~/Documents'],
  ['Cookie: a=1; rm -rf ~/Documents', 'rm -rf ~/Documents'],
  [`echo 'TOKEN="'; rm -rf ~/Documents; echo '"'`, 'rm -rf ~/Documents'],
  ['PASSWORD="a"; rm -rf ~/Documents', 'rm -rf ~/Documents'],
  ['curl -u a:b"; rm -rf ~/Documents; echo "c" x.com', 'rm -rf ~/Documents'],
  ['echo -----BEGIN PRIVATE KEY-----; rm -rf ~/Documents', 'rm -rf ~/Documents'],
  ['echo -----BEGIN PRIVATE KEY-----\nrm -rf ~/Documents', 'rm -rf ~/Documents'],
  ['rm -rf ./cache/../../../Users/dev/Documents/thesis/papers/final/chapters/one/two/three/four', '../../../Users/dev/Documents/thesis'],
  ['MONKEY=banana ./run', 'banana'],
  [`${'a%41 '.repeat(80)} rm -rf %2e%2e`, 'rm -rf %2e%2e'],
  ['-print0', '-print0'],
];

for (const [command, visible] of STAYS_VISIBLE) {
  test(`a person still reads what runs in: ${command.slice(0, 48)}`, () => {
    assert.ok(forDisplay(command).text.includes(visible), forDisplay(command).text);
  });
}

test('the display says when a pattern changed the text', () => {
  assert.deepEqual(forDisplay('echo hi'), { text: 'echo hi', warnings: [], truncated: false, redacted: false });
  const display = forDisplay('TOKEN=abc ./run');
  assert.equal(display.text, 'TOKEN=[redacted] ./run');
  assert.equal(display.redacted, true);
});

test('text past the scanned size is cut, and the display says so', () => {
  const long = `${'x'.repeat(100000)} TOKEN=abc`;
  assert.ok(!redact(long).includes('abc'));
  assert.ok(redact(long).length < 20000);
  const display = forDisplay(`echo ${'word '.repeat(10000)}`);
  assert.equal(display.truncated, true);
  assert.ok(display.warnings.includes('too long to show in full'), display.warnings.join());
});

test('lines with no command in them raise a warning', () => {
  assert.ok(forDisplay(`${'# note\n'.repeat(900)}rm -rf victim`).warnings.includes('long run of lines with no command in them'));
  assert.ok(forDisplay(`${':\ntrue\n'.repeat(10)}rm -rf victim`).warnings.includes('long run of lines with no command in them'));
  assert.ok(forDisplay(`${'ls\n'.repeat(100)}rm -rf victim`).warnings.includes('many lines to read'));
  assert.deepEqual(forDisplay('# one comment\nls\n\npwd').warnings, []);
});

const toolCases = [
  ['Write', { file_path: '/Users/dev/.SAYSO/keys.json' }, 'self'],
  ['Read', { file_path: '/Users/dev/.SAYSO/keys.json' }, 'self'],
  ['Write', { file_path: '/Users/dev/.claude-work/main/settings.json' }, 'self'],
  ['Edit', { file_path: '/Users/dev/.claude-work/nested/settings.local.json' }, 'self'],
  ['Write', { file_path: '/Users/dev/.claude/notes.json' }, null],
  ['Grep', { pattern: 'x', path: '/Users/dev/.sayso' }, 'self'],
  ['Glob', { pattern: '*', path: '/Users/dev/.SAYSO' }, 'self'],
  ['Grep', { pattern: 'x', path: 'src' }, null],
  ['Bash', { command: 'rm -rf /' }, 'catastrophic'],
  ['Monitor', { command: 'rm -rf x' }, 'destructive'],
  ['Bash', { command: 'ls' }, null],
  ['Write', { file_path: '/Users/dev/.sayso/x' }, 'self'],
  ['Edit', { file_path: '/Users/dev/.claude/settings.json' }, 'self'],
  ['MultiEdit', { file_path: '.claude/settings.local.json' }, 'self'],
  ['Write', { file_path: '/Library/Application Support/ClaudeCode/managed-settings.json' }, 'self'],
  ['Write', { file_path: '/Users/dev/.claude.json' }, 'self'],
  ['NotebookEdit', { notebook_path: '/Users/dev/.sayso/n.ipynb' }, 'self'],
  ['Write', { file_path: '~/.ssh/authorized_keys' }, 'destructive'],
  ['Edit', { file_path: '/Users/dev/.bashrc' }, 'destructive'],
  ['Edit', { file_path: '/Users/dev/.zshrc' }, 'destructive'],
  ['Edit', { file_path: '/Users/dev/.profile' }, 'destructive'],
  ['Edit', { file_path: '/Users/dev/.bash_profile' }, 'destructive'],
  ['Write', { file_path: '/etc/hosts' }, 'destructive'],
  ['Write', { file_path: '/private/etc/hosts' }, 'destructive'],
  ['Write', { file_path: '/Users/dev/Library/LaunchAgents/x.plist' }, 'destructive'],
  ['Write', { file_path: '/Library/LaunchDaemons/x.plist' }, 'destructive'],
  ['Write', { file_path: 'src/a.js' }, null],
  ['Write', { file_path: '../other/.bashrc' }, null],
  ['Read', { file_path: '/Users/dev/.ssh/id_rsa' }, 'credentials'],
  ['Read', { file_path: '/Users/dev/.aws/credentials' }, 'credentials'],
  ['Read', { file_path: '/Users/dev/.ssh/id_rsa.pub' }, null],
  ['Read', { file_path: '/Users/dev/.sayso/token' }, 'self'],
  ['Read', { file_path: 'README.md' }, null],
  ['mcp__sayso__ask', {}, null],
  ['mcp__sayso__delete_everything', {}, 'outward'],
  ['mcp__shell__run_command', { command: 'rm -rf victim' }, 'destructive'],
  ['mcp__fs__write_file', { path: '/Users/dev/.claude/settings.json', content: '{}' }, 'self'],
  ['mcp__fs__get_file', { file_path: '/Users/dev/.sayso/keys.json' }, 'self'],
  ['mcp__fs__get_file', { path: '/Users/dev/.ssh/id_rsa' }, 'credentials'],
  ['mcp__db__q', { sql: 'DROP TABLE users' }, 'destructive'],
  ['mcp__db__q', { query: 'DROP TABLE users' }, 'destructive'],
  ['mcp__x__do', { steps: [{ deep: { cmd: 'rm -rf /' } }] }, 'catastrophic'],
  ['mcp__x__do', { script: 'rm -rf victim' }, 'destructive'],
  ['mcp__x__exec', {}, 'opaque'],
  ['mcp__x__shell', {}, 'opaque'],
  ['mcp__x__run', {}, 'opaque'],
  ['mcp__x__runCode', {}, 'opaque'],
  ['mcp__x__write_doc', {}, 'opaque'],
  ['mcp__x__send_command', {}, 'outward'],
  ['mcp__x__prune_cache', {}, null],
  ['mcp__x__truncate_text', {}, null],
  ['mcp__x__get_command', {}, null],
  ['mcp__x__list_shells', {}, null],
  ['mcp__db__search', { query: 'how to drop table' }, null],
  ['mcp__x__do', { command: 'ls' }, null],
  ['ExitWorktree', { action: 'remove', discard_changes: true }, 'destructive'],
  ['ExitWorktree', { action: 'keep' }, null],
  ['ExitWorktree', { action: 'remove', discard_changes: false }, null],
  ['Read', { file_path: '/Users/dev/.git-credentials' }, 'credentials'],
  ['Read', { file_path: '/srv/app/.env' }, 'credentials'],
  ['Read', { file_path: '.env.production' }, 'credentials'],
  ['Read', { file_path: '.env.example' }, null],
  ['Write', { file_path: '/Users/dev/.gitconfig', content: '[core]\n fsmonitor=/tmp/e' }, 'destructive'],
  ['Write', { file_path: '/Users/dev/.zlogin', content: 'x' }, 'destructive'],
  ['Write', { file_path: '/Users/dev/project/.git/hooks/pre-commit', content: 'x' }, 'destructive'],
  ['Write', { file_path: '.git/hooks/pre-commit', content: 'x' }, 'destructive'],
  ['Write', { file_path: '/Users/dev/.config/fish/config.fish', content: 'x' }, 'destructive'],
  ['mcp__github__delete_repo', {}, 'outward'],
  ['mcp__gmail__send_message', {}, 'outward'],
  ['mcp__gmail__sendMessage', {}, 'outward'],
  ['mcp__x__publish_post', {}, 'outward'],
  ['mcp__x__deploy', {}, 'outward'],
  ['mcp__x__pay_invoice', {}, 'outward'],
  ['mcp__x__dropTable', {}, 'outward'],
  ['mcp__x__dropdown_options', {}, null],
  ['mcp__x__get_payload', {}, null],
  ['mcp__github__get_repo', { body: 'delete everything' }, null],
  ['Glob', { pattern: '**/*' }, null],
  ['WebFetch', { url: 'https://example.com' }, null],
];

for (const [tool, input, risk] of toolCases) {
  test(`tool ${tool} ${JSON.stringify(input)} is ${risk}`, () => {
    assert.equal(classifyToolCall(tool, input, CTX)?.risk ?? null, risk);
  });
}

test('file tool verdict names its reason', () => {
  assert.deepEqual(classifyToolCall('Write', { file_path: '/Users/dev/.bashrc' }, CTX), {
    risk: 'destructive',
    why: ['write to a shell startup or system path'],
  });
});

test('a corpus-sized sweep stays well under a millisecond per command', () => {
  const all = [...dangerous.map((entry) => decode(entry.source)), ...safe.map(decode)];
  const start = performance.now();
  for (let round = 0; round < 20; round++) for (const command of all) classifyShell(command, CTX);
  const perCommand = (performance.now() - start) / (20 * all.length);
  assert.ok(perCommand < 1, `mean ${perCommand.toFixed(3)} ms per command`);
});

test('measure tool reports aggregates and keeps command text off stdout', () => {
  const dir = mkdtempSync(join(tmpdir(), 'sayso-measure-'));
  try {
    const assistant = (id, command) => JSON.stringify({ type: 'assistant', cwd: '/x', message: { content: [{ type: 'tool_use', id, name: 'Bash', input: { command } }] } });
    writeFileSync(join(dir, 'a.jsonl'), `${assistant('1', 'rm -rf private-client-name')}\n${assistant('2', 'ls')}\n${assistant('2', 'ls')}\n`);
    const tool = fileURLToPath(new URL('../tools/measure-classifier.mjs', import.meta.url));
    const out = join(dir, 'sample.jsonl');
    const run = spawnSync(process.execPath, [tool, '--dir', dir, '--show-flagged', '5', '--out', out], { encoding: 'utf8' });
    assert.equal(run.status, 0);
    assert.ok(!run.stdout.includes('private-client-name'));
    const report = JSON.parse(run.stdout);
    assert.equal(report.total_commands, 2);
    assert.equal(report.flagged_per_risk.destructive, 1);
    assert.equal(report.flagged_rate, 0.5);
    assert.deepEqual(report.top_reasons, [{ why: 'recursive delete', count: 1 }]);
    assert.equal(JSON.parse(readFileSync(out, 'utf8')).command, 'rm -rf private-client-name');
    const refused = spawnSync(process.execPath, [tool, '--dir', dir, '--show-flagged', '5'], { encoding: 'utf8' });
    assert.equal(refused.status, 2);
    assert.equal(refused.stdout, '');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('mcp: a command is read in every shape servers use', () => {
  for (const input of [{ code: ['rm', '-rf', 'victim'] }, { code: 'rm', args: ['-rf', 'victim'] }, { code: 'rm -rf victim' }, { command: ['rm', '-rf', 'victim'] }, { command: 'rm', arguments: ['-rf', 'victim'] }, { args: ['rm', '-rf', 'victim'] }, { program: 'rm', args: ['-rf', 'victim'] }, { cmdline: 'rm -rf victim' }, { exec: 'rm -rf victim' }, { run: 'rm -rf victim' }, { code: 'rm -rf victim' }, { commands: ['ls', 'rm -rf victim'] }]) {
    assert.equal(classifyToolCall('mcp__x__do', input, CTX)?.risk, 'destructive', JSON.stringify(input));
  }
  assert.equal(classifyToolCall('mcp__x__do', { command: ['ls', '-la'] }, CTX), null);
  assert.equal(classifyToolCall('mcp__x__do', { code: 'const a = b > c ? (x) => x + 1 : await fetch(`/x/${id}`); if (a > b) log(a)' }, CTX), null, 'shell syntax says nothing about code in another language');
  assert.equal(classifyToolCall('mcp__x__do', { code: "require('fs').rmSync('victim', { recursive: true })" }, CTX)?.risk, 'opaque');
});

test('mcp: a tool named for what it does is held, and a read of the same thing is not', () => {
  for (const name of ['rm', 'rmdir', 'unlink', 'erase', 'truncate', 'move_file', 'rename', 'edit_file', 'patch', 'save_file', 'append', 'create_file', 'spawn', 'spawn_process', 'launch', 'system', 'sh', 'zsh', 'python', 'node', 'applescript', 'invoke', 'kill', 'stop_process', 'push', 'force_push', 'reset', 'merge_pull_request', 'kubectl', 's3_rm', 'refund', 'forward']) {
    assert.ok(classifyToolCall(`mcp__x__${name}`, {}, CTX), name);
  }
  for (const name of ['get_node', 'list_files', 'truncate_text', 'read_file', 'search', 'create_issue']) assert.equal(classifyToolCall(`mcp__x__${name}`, {}, CTX), null, name);
});

test('mcp: paths and sql under the keys servers use', () => {
  assert.equal(classifyToolCall('mcp__x__do', { location: '~/.claude/settings.json' }, CTX)?.risk, 'self');
  for (const input of [{ uri: 'file:///Users/dev/.ssh/id_rsa' }, { pathname: '/Users/dev/.ssh/id_rsa' }]) assert.equal(classifyToolCall('mcp__x__do', input, CTX)?.risk, 'credentials', JSON.stringify(input));
  assert.equal(classifyToolCall('mcp__x__do', { url: 'https://example.com/a' }, CTX), null);
  for (const input of [{ query: '/**/drop table users' }, { query: '(drop table users)' }, { query: '-- x\ndrop table users' }, { sql: 'UPDATE users SET a=1' }, { q: 'drop table users' }]) assert.equal(classifyToolCall('mcp__db__do', input, CTX)?.risk, 'destructive', JSON.stringify(input));
  assert.equal(classifyToolCall('mcp__db__do', { sql: "UPDATE users SET a=1 WHERE id=2" }, CTX), null);
});

test('characters with no glyph of their own raise a warning, whichever list they would miss', () => {
  for (const cp of [0x180b, 0x180f, 0x1d159, 0x1bca0, 0x13430, 0x110bd, 0xfffc, 0x0336, 0x20e3, 0xe000]) {
    const { warnings, text } = forDisplay(`rm -rf a${String.fromCodePoint(cp)}b`);
    assert.ok(warnings.includes('invisible characters'), cp.toString(16));
    assert.ok(text.includes('⟦U+'), cp.toString(16));
  }
});

test('a lone backslash is filler, and many lines are called many well before they fill a phone', () => {
  assert.ok(forDisplay(`rm -rf ./cache \\\n${'\\\n'.repeat(77)}~/Documents`).warnings.includes('long run of lines with no command in them'));
  assert.ok(forDisplay(`${'echo ok\n'.repeat(40)}rm -rf victim`).warnings.includes('many lines to read'));
});
