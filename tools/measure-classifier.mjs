#!/usr/bin/env node
import { createReadStream, readdirSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { parseArgs } from 'node:util';
import { pathToFileURL } from 'node:url';
import { classifyShell, classifyToolCall, RISK_ORDER } from '../src/classify.mjs';

const { values: options } = parseArgs({
  options: {
    dir: { type: 'string' },
    'max-files': { type: 'string' },
    'show-flagged': { type: 'string' },
    out: { type: 'string' },
    against: { type: 'string' },
  },
});

if (!options.dir) {
  console.error('usage: measure-classifier --dir <path> [--max-files N] [--show-flagged N --out path] [--against other/classify.mjs]');
  process.exit(2);
}
const sampleSize = Number(options['show-flagged'] ?? 0);
if (sampleSize > 0 && !options.out) {
  console.error('--show-flagged needs --out, flagged commands never print to stdout');
  process.exit(2);
}

const against = options.against ? await import(pathToFileURL(resolve(options.against)).href) : null;

function transcriptFiles(dir) {
  const found = [];
  const stack = [dir];
  while (stack.length > 0) {
    const current = stack.pop();
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const path = join(current, entry.name);
      if (entry.isDirectory()) stack.push(path);
      else if (entry.isFile() && entry.name.endsWith('.jsonl')) found.push(path);
    }
  }
  return found;
}

function newestFirst(paths) {
  return paths
    .map((path) => ({ path, mtime: statSync(path).mtimeMs }))
    .sort((a, b) => b.mtime - a.mtime)
    .map((entry) => entry.path);
}

function percentile(sorted, fraction) {
  return sorted.length === 0 ? 0 : sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * fraction))];
}

const round = (value, digits) => Number(value.toFixed(digits));

const allFiles = newestFirst(transcriptFiles(options.dir));
const files = options['max-files'] ? allFiles.slice(0, Number(options['max-files'])) : allFiles;
const home = homedir();
const stateDir = join(home, '.sayso');

const seenToolUses = new Set();
const uniqueCommands = new Set();
const flaggedUnique = new Set();
const flaggedPerRisk = Object.fromEntries(RISK_ORDER.map((risk) => [risk, 0]));
const reasonCounts = new Map();
const timingsMicros = [];
const sample = [];
let flaggedTotal = 0;
let seenFlagged = 0;
let unreadableLines = 0;
let newlyFlagged = 0;
const newReasonCounts = new Map();
const otherTools = { total: 0, flagged: 0, per_risk: Object.fromEntries(RISK_ORDER.map((risk) => [risk, 0])), new_flagged: 0 };

const bump = (counts, why) => counts.set(why, (counts.get(why) ?? 0) + 1);

function keepInSample(item) {
  seenFlagged++;
  if (sample.length < sampleSize) sample.push(item);
  else if (sampleSize > 0) {
    const slot = Math.floor(Math.random() * seenFlagged);
    if (slot < sampleSize) sample[slot] = item;
  }
}

function record(command, cwd) {
  uniqueCommands.add(command);
  const ctx = { home, cwd: cwd ?? process.cwd(), stateDir };
  const start = process.hrtime.bigint();
  const verdict = classifyShell(command, ctx);
  timingsMicros.push(Number(process.hrtime.bigint() - start) / 1000);
  if (!verdict) return;
  flaggedTotal++;
  flaggedUnique.add(command);
  flaggedPerRisk[verdict.risk]++;
  for (const why of verdict.why) bump(reasonCounts, why);
  const isNew = against !== null && !against.classifyShell(command, ctx);
  if (isNew) {
    newlyFlagged++;
    for (const why of verdict.why) bump(newReasonCounts, why);
  }
  if (against === null || isNew) keepInSample({ risk: verdict.risk, why: verdict.why, command });
}

function recordOtherTool(name, input, cwd) {
  otherTools.total++;
  const ctx = { home, cwd: cwd ?? process.cwd(), stateDir };
  const verdict = classifyToolCall(name, input, ctx);
  if (!verdict) return;
  otherTools.flagged++;
  otherTools.per_risk[verdict.risk]++;
  if (against === null) return;
  if (against.classifyToolCall(name, input, ctx)) return;
  otherTools.new_flagged++;
  for (const why of verdict.why) bump(newReasonCounts, why);
  keepInSample({ risk: verdict.risk, why: verdict.why, tool: name, input });
}

for (const file of files) {
  const lines = createInterface({ input: createReadStream(file), crlfDelay: Number.POSITIVE_INFINITY });
  for await (const line of lines) {
    if (!line.includes('"tool_use"')) continue;
    let entry;
    try {
      entry = JSON.parse(line);
    } catch {
      unreadableLines++;
      continue;
    }
    if (entry.type !== 'assistant' || !Array.isArray(entry.message?.content)) continue;
    for (const block of entry.message.content) {
      if (block.type !== 'tool_use') continue;
      if (block.id && seenToolUses.has(block.id)) continue;
      if (block.id) seenToolUses.add(block.id);
      if (block.name !== 'Bash') recordOtherTool(block.name, block.input ?? {}, entry.cwd);
      else if (typeof block.input?.command === 'string') record(block.input.command, entry.cwd);
    }
  }
}

if (sampleSize > 0) writeFileSync(options.out, `${sample.map((item) => JSON.stringify(item)).join('\n')}\n`, { mode: 0o600 });

timingsMicros.sort((a, b) => a - b);
const total = timingsMicros.length;
console.log(
  JSON.stringify(
    {
      files_read: files.length,
      unreadable_lines: unreadableLines,
      total_commands: total,
      unique_commands: uniqueCommands.size,
      flagged_total: flaggedTotal,
      flagged_per_risk: flaggedPerRisk,
      flagged_rate: total === 0 ? 0 : round(flaggedTotal / total, 5),
      flagged_rate_unique: uniqueCommands.size === 0 ? 0 : round(flaggedUnique.size / uniqueCommands.size, 5),
      p50_micros: round(percentile(timingsMicros, 0.5), 1),
      p99_micros: round(percentile(timingsMicros, 0.99), 1),
      top_reasons: [...reasonCounts].sort((a, b) => b[1] - a[1]).slice(0, 15).map(([why, count]) => ({ why, count })),
      other_tools: otherTools,
      ...(against && {
        new_flagged: newlyFlagged,
        new_reasons: [...newReasonCounts].sort((a, b) => b[1] - a[1]).slice(0, 40).map(([why, count]) => ({ why, count })),
      }),
    },
    null,
    2,
  ),
);
