import { SEVERITY_ORDER, type Finding, type Severity } from "./types.js";

const WEIGHTS: Record<Severity, number> = {
  critical: 40,
  high: 25,
  medium: 10,
  low: 3,
  info: 0,
};

/** Crude but honest: sum of severity weights, capped at 100. */
export function riskScore(findings: Finding[]): number {
  let score = 0;
  for (const f of findings) {
    // cap the damage any single rule can do to the score
    score += WEIGHTS[f.severity];
  }
  return Math.min(100, score);
}

export function grade(score: number, hasCritical: boolean = false): "A" | "B" | "C" | "D" | "F" {
  if (hasCritical) return "F"; // any live critical finding means "act now", regardless of score
  if (score <= 4) return "A";
  if (score <= 14) return "B";
  if (score <= 29) return "C";
  if (score <= 49) return "D";
  return "F";
}

export function worstSeverity(findings: Finding[]): Severity | null {
  let worst: Severity | null = null;
  for (const f of findings) {
    if (worst === null || SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[worst]) {
      worst = f.severity;
    }
  }
  return worst;
}
