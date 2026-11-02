import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { classifyShell, classifyToolCall, RISK_ORDER } from '../src/classify.mjs';

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

test('an adversarial command stays fast', () => {
  const nested = Array.from({ length: 2000 }, () => '"x=y z"').join(' ');
  for (const command of [`tool ${nested}`, `${'a -- '.repeat(3000)}x`, `sh -c "${'sh -c '.repeat(1500)}x"`]) {
    const start = performance.now();
    classifyShell(command, CTX);
    assert.ok(performance.now() - start < 1500, `took ${performance.now() - start} ms`);
  }
});

const toolCases = [
  ['Write', { file_path: '/Users/dev/.SAYSO/keys.json' }, 'self'],
  ['Read', { file_path: '/Users/dev/.SAYSO/keys.json' }, 'self'],
  ['Write', { file_path: '/Users/dev/.claude-work/settings.json' }, 'self'],
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
  ['mcp__sayso__delete_everything', {}, null],
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
