import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scenarios } from './scenarios.js';

/**
 * 把所有合成场景写成真实的 pcap 文件，供 tshark 对账脚本和手工验证使用。
 * 这些文件可以直接用 Wireshark 打开。
 */
const outputDir = join(dirname(fileURLToPath(import.meta.url)), '../../fixtures');
mkdirSync(outputDir, { recursive: true });

let count = 0;
for (const [name, build] of Object.entries(scenarios)) {
  const bytes = build();
  const path = join(outputDir, `${toKebabCase(name)}.pcap`);
  writeFileSync(path, bytes);
  console.log(`${path}  (${bytes.length} 字节)`);
  count += 1;
}
console.log(`\n共写出 ${count} 个夹具到 ${outputDir}`);

function toKebabCase(value: string): string {
  return value.replace(/([a-z0-9])([A-Z])/g, '$1-$2').toLowerCase();
}
