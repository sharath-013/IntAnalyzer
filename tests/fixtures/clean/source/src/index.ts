import { clamp } from "./util";

export function percent(part: number, total: number): number {
  if (total === 0) return 0;
  return clamp(Math.round((part / total) * 100), 0, 100);
}

export { clamp };
