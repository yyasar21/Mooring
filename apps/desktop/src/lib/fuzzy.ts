/**
 * Subsequence fuzzy score. Higher is better; null means no match.
 * Consecutive and word-start hits score more, so "w01" ranks "web01" above "wiki-backup-01".
 */
export function fuzzyScore(query: string, text: string): number | null {
  const q = query.toLowerCase();
  const t = text.toLowerCase();
  if (q.length === 0) return 0;
  const direct = t.indexOf(q);
  if (direct >= 0) return 1000 - direct * 2 - (t.length - q.length);
  let score = 0;
  let ti = 0;
  let prev = -2;
  for (const ch of q) {
    const found = t.indexOf(ch, ti);
    if (found < 0) return null;
    const boundary = found === 0 || /[\s.\-_/:]/.test(t.charAt(found - 1));
    score += found === prev + 1 ? 6 : boundary ? 4 : 1;
    prev = found;
    ti = found + 1;
  }
  return score - Math.floor(t.length / 8);
}

/** Best score of a query against several fields. */
export function bestScore(query: string, fields: readonly string[]): number | null {
  let best: number | null = null;
  for (const f of fields) {
    const s = fuzzyScore(query, f);
    if (s !== null && (best === null || s > best)) best = s;
  }
  return best;
}
