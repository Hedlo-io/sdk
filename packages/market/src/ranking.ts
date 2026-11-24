export interface RankStats {
  id: string;
  sales30: number;
  views30: number;
  ratingSum: number;
  ratingCount: number;
  refunds90: number;
  sales90: number;
  updatedAt: number;
  publishedAt: number;
  compatible: boolean | null;
  promoted: boolean;
  advisoryOpen: boolean;
}

export const PRIOR_RATING = 3.8;
export const PRIOR_WEIGHT = 8;
export const SPONSORED_MAX = 2;
export const SPONSORED_MIN_SCORE = 0.35;
const DAY = 86_400_000;

export function bayesRating(sum: number, count: number): number {
  return (PRIOR_RATING * PRIOR_WEIGHT + sum) / (PRIOR_WEIGHT + count);
}

export interface Ranked {
  id: string;
  score: number;
  sponsored: boolean;
  fresh: boolean;
}

export function score(s: RankStats, now: number): number {
  const velocity = Math.log1p(s.sales30) / Math.log1p(200);
  const conversion = s.views30 >= 30 ? Math.min(1, s.sales30 / s.views30 / 0.08) : 0.4;
  const rating = (bayesRating(s.ratingSum, s.ratingCount) - 1) / 4;
  const age = (now - s.updatedAt) / DAY;
  const freshness = Math.exp(-Math.max(0, age) / 120);
  const refundRate = s.sales90 >= 5 ? s.refunds90 / s.sales90 : 0;
  const penalty = Math.min(0.6, refundRate * 2) + (s.advisoryOpen ? 0.5 : 0);
  const compat = s.compatible === false ? 0.3 : 1;
  return Math.max(0, (0.34 * velocity + 0.16 * conversion + 0.3 * rating + 0.2 * freshness) * (1 - penalty) * compat);
}

export function rank(items: readonly RankStats[], now: number, o: { exploreEvery?: number; newWithinDays?: number } = {}): Ranked[] {
  const every = o.exploreEvery ?? 6;
  const newWithin = (o.newWithinDays ?? 30) * DAY;
  const scored = items.map((s) => ({ s, score: score(s, now) }));
  const byScore = (a: { score: number; s: RankStats }, b: { score: number; s: RankStats }) => b.score - a.score || a.s.id.localeCompare(b.s.id);
  const sponsored = scored.filter((x) => x.s.promoted && x.score >= SPONSORED_MIN_SCORE && !x.s.advisoryOpen).sort(byScore).slice(0, SPONSORED_MAX);
  const taken = new Set(sponsored.map((x) => x.s.id));
  const fresh = scored.filter((x) => !taken.has(x.s.id) && now - x.s.publishedAt <= newWithin && x.s.sales30 < 10).sort(byScore);
  const rest = scored.filter((x) => !taken.has(x.s.id)).sort(byScore);
  const out: Ranked[] = sponsored.map((x) => ({ id: x.s.id, score: x.score, sponsored: true, fresh: false }));
  const used = new Set(taken);
  let organic = 0;
  for (const x of rest) {
    if (used.has(x.s.id)) continue;
    if (organic > 0 && organic % every === every - 1) {
      const f = fresh.find((y) => !used.has(y.s.id));
      if (f) {
        out.push({ id: f.s.id, score: f.score, sponsored: false, fresh: true });
        used.add(f.s.id);
        organic++;
      }
    }
    if (used.has(x.s.id)) continue;
    out.push({ id: x.s.id, score: x.score, sponsored: false, fresh: false });
    used.add(x.s.id);
    organic++;
  }
  return out;
}
