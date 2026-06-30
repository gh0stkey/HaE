import { ScanRule } from '../types';

export function chunkArray<T>(array: T[], size: number): T[][] {
  if (size <= 0) {
    return [array];
  }
  const chunks: T[][] = [];
  for (let i = 0; i < array.length; i += size) {
    chunks.push(array.slice(i, i + size));
  }
  return chunks;
}

export function groupRulesByPattern(rules: ScanRule[]): Map<string, ScanRule[]> {
  const map = new Map<string, ScanRule[]>();
  for (const rule of rules) {
    const key = `${rule.regex}::${rule.sensitive}`;
    if (!map.has(key)) {
      map.set(key, []);
    }
    map.get(key)!.push(rule);
  }
  return map;
}
