#!/usr/bin/env node
/**
 * tshark 对账：把本工具的异常判定与 tshark 的 tcp.analysis.* 字段逐包比对。
 *
 * 「自动给结论」的前提是结论正确，否则对新手的伤害比 Wireshark 更大。
 * 重传 / 乱序 / 零窗口的判定都含启发式成分，必须有一个外部基准来校验。
 *
 * tshark 不是必须的：没装就跳过并提示安装方式，不阻塞其他流程。
 */
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const FIXTURE_DIR = join(import.meta.dirname, '../packages/core/fixtures');
/** 真实抓包夹具。合成夹具只能验证「我们以为现实长什么样」，真实文件才校得出偏差 */
const TESTDATA_DIR = join(import.meta.dirname, '../packages/core/testdata');
const CORE_ENTRY = join(import.meta.dirname, '../packages/core/dist/index.js');

/** 我方异常种类 → tshark 字段。keep-alive 与 window-update 不参与对账 */
const FIELD_MAP = [
  { ours: 'retransmission', tshark: 'tcp.analysis.retransmission', label: '重传' },
  { ours: 'fast-retransmission', tshark: 'tcp.analysis.fast_retransmission', label: '快速重传' },
  { ours: 'suspected-out-of-order', tshark: 'tcp.analysis.out_of_order', label: '乱序' },
  { ours: 'zero-window', tshark: 'tcp.analysis.zero_window', label: '零窗口' },
  { ours: 'duplicate-ack', tshark: 'tcp.analysis.duplicate_ack', label: '重复确认' },
  { ours: 'lost-segment', tshark: 'tcp.analysis.lost_segment', label: '丢段' },
];

function hasTshark() {
  const probe = spawnSync('tshark', ['-v'], { stdio: 'ignore' });
  return probe.status === 0;
}

if (!hasTshark()) {
  console.log('⏭  未检测到 tshark，跳过对账。');
  console.log('   如需启用正确性校验：brew install wireshark');
  process.exit(0);
}

if (!existsSync(CORE_ENTRY)) {
  console.error('✗ 未找到 core 的构建产物，请先执行：npm run build -w @tcpview/core');
  process.exit(1);
}

if (!existsSync(FIXTURE_DIR) && !existsSync(TESTDATA_DIR)) {
  console.error('✗ 未找到夹具目录，请先执行：npm run fixtures');
  process.exit(1);
}

const { analyze } = await import(pathToFileURL(CORE_ENTRY).href);

/** 用 tshark 读出每个包上被标记的分析字段 */
function runTshark(file) {
  const fields = FIELD_MAP.flatMap((entry) => ['-e', entry.tshark]);
  const output = execFileSync(
    'tshark',
    ['-r', file, '-T', 'fields', '-e', 'frame.number', ...fields, '-E', 'separator=|'],
    { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 },
  );

  const perPacket = new Map();
  for (const line of output.split('\n')) {
    if (!line.trim()) continue;
    const columns = line.split('|');
    // tshark 的 frame.number 从 1 开始，我们的包序号从 0 开始
    const index = Number(columns[0]) - 1;
    const kinds = new Set();
    FIELD_MAP.forEach((entry, i) => {
      if ((columns[i + 1] ?? '').trim() !== '') kinds.add(entry.ours);
    });
    perPacket.set(index, kinds);
  }
  return perPacket;
}

function collectOurs(result) {
  const perPacket = new Map();
  for (const connection of result.connections) {
    for (const packet of connection.packets) {
      const kinds = new Set(packet.anomalies.map((a) => a.kind));
      perPacket.set(packet.packetIndex, kinds);
    }
  }
  return perPacket;
}

/** 合成夹具与真实抓包一并对账；真实文件加前缀标出来，差异归因时能立刻分辨 */
function collectCaptures() {
  const captures = [];
  for (const [dir, label] of [
    [FIXTURE_DIR, ''],
    [TESTDATA_DIR, '真实抓包 '],
  ]) {
    if (!existsSync(dir)) continue;
    const names = readdirSync(dir)
      .filter((name) => name.endsWith('.pcap') || name.endsWith('.pcapng'))
      .sort();
    for (const name of names) {
      captures.push({ label: `${label}${name}`, path: join(dir, name) });
    }
  }
  return captures;
}

const captures = collectCaptures();
let totalMismatches = 0;
let totalPackets = 0;

console.log(`对账 ${captures.length} 个抓包文件（基准：tshark）\n`);

for (const { label, path } of captures) {
  const ours = collectOurs(analyze(new Uint8Array(readFileSync(path))));
  const theirs = runTshark(path);

  const rows = [];
  const indices = new Set([...ours.keys(), ...theirs.keys()]);

  for (const index of [...indices].sort((a, b) => a - b)) {
    totalPackets += 1;
    const oursKinds = ours.get(index) ?? new Set();
    const theirsKinds = theirs.get(index) ?? new Set();

    for (const entry of FIELD_MAP) {
      const weSay = oursKinds.has(entry.ours);
      const theySay = theirsKinds.has(entry.ours);
      if (weSay === theySay) continue;

      rows.push(
        `    包 #${index}  ${entry.label}：` +
          (weSay ? '我们标了、tshark 没标' : 'tshark 标了、我们没标'),
      );
    }
  }

  if (rows.length === 0) {
    console.log(`  ✓ ${label}`);
  } else {
    totalMismatches += rows.length;
    console.log(`  ✗ ${label}  ${rows.length} 处差异`);
    for (const row of rows) console.log(row);
  }
}

console.log(`\n共比对 ${totalPackets} 个包，发现 ${totalMismatches} 处差异。`);

if (totalMismatches > 0) {
  console.log(
    '\n差异不一定代表我们错了——乱序与重传的区分本身是启发式的，tshark 也在猜。\n' +
      '但每一处差异都应当能解释清楚原因，不能放着不管。',
  );
}
