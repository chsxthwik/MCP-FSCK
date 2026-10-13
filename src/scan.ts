import { applyBaseline } from "./baseline.js";
import { enumerateTools, mapPool } from "./deep.js";
import { ALL_RULES } from "./rules/index.js";
import { grade, riskScore } from "./score.js";
import { SEVERITY_ORDER, type ConfigFile, type DeepResult, type Finding, type GradedTarget, type ParsedServer, type RuleContext, type ScanOptions, type ScanResult } from "./types.js";

function keyOf(server: ParsedServer): string {
  return `${server.source}::${server.name}`;
}

function ruleWarning(ruleId: string, where: string, err: unknown): string {
  const message = err instanceof Error ? err.message : String(err);
  return `${ruleId} failed on ${where}: ${message}`;
}

export async function scan(options: ScanOptions, configs: ConfigFile[]): Promise<ScanResult> {
  const allServers = configs.flatMap((c) => c.servers);

  // ---- deep mode: live tool enumeration -------------------------------
  const deep = new Map<string, DeepResult>();
  if (options.deep) {
    const targets = allServers.filter((s) => s.transport === "stdio" || s.transport === "http" || s.transport === "sse");
    const version = options.clientVersion ?? "0.0.0";
    const results = await mapPool(targets, 4, (server) => enumerateTools(server, options.timeoutMs, version));
    for (let i = 0; i < targets.length; i += 1) {
      deep.set(keyOf(targets[i]!), results[i]!);
    }
  }

  // ---- rules ----------------------------------------------------------
  const context: RuleContext = { allServers, deep };
  const findings: Finding[] = [];
  const warnings: string[] = [];
  for (const probed of deep.values()) {
    if (probed.warning !== undefined) warnings.push(`${probed.server}: ${probed.warning}`);
  }

  for (const config of configs) {
    if (!config.exists) continue;
    for (const rule of ALL_RULES) {
      if (rule.runConfig === undefined) continue;
      let raws;
      try {
        raws = rule.runConfig(config);
      } catch (err) {
        warnings.push(ruleWarning(rule.meta.id, config.path, err));
        continue;
      }
      for (const raw of raws) {
        findings.push({
          ruleId: rule.meta.id,
          ruleName: rule.meta.name,
          severity: raw.severity ?? rule.meta.severity,
          title: raw.title,
          detail: raw.detail,
          evidence: raw.evidence,
          remediation: raw.remediation ?? rule.meta.remediation,
          source: config.path,
          deep: false,
        });
      }
    }
    for (const server of config.servers) {
      for (const rule of ALL_RULES) {
        let raws;
        try {
          raws = rule.run(server, context);
        } catch (err) {
          warnings.push(ruleWarning(rule.meta.id, `${server.name} (${config.path})`, err));
          continue;
        }
        for (const raw of raws) {
          findings.push({
            ruleId: rule.meta.id,
            ruleName: rule.meta.name,
            severity: raw.severity ?? rule.meta.severity,
            title: raw.title,
            detail: raw.detail,
            evidence: raw.evidence,
            remediation: raw.remediation ?? rule.meta.remediation,
            source: server.source,
            server: server.name,
            deep: rule.meta.scope === "deep",
          });
        }
      }
    }
  }

  findings.sort((a, b) => {
    const bySeverity = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
    if (bySeverity !== 0) return bySeverity;
    const bySource = a.source.localeCompare(b.source);
    if (bySource !== 0) return bySource;
    const byServer = (a.server ?? "").localeCompare(b.server ?? "");
    if (byServer !== 0) return byServer;
    return a.ruleId.localeCompare(b.ruleId);
  });

  // ---- baseline suppressions ----------------------------------------
  const { kept, suppressed } = applyBaseline(findings, options.baseline ?? []);

  const score = riskScore(kept);
  const summary = {
    configsScanned: configs.filter((c) => c.exists).length,
    serversFound: allServers.length,
    findings: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    suppressed: suppressed.length,
    grade: grade(score, kept.some((finding) => finding.severity === "critical")),
    score,
    disabled: configs.reduce((count, config) => count + (config.skipped?.length ?? 0), 0),
  } satisfies ScanResult["summary"];
  for (const f of kept) summary.findings[f.severity] += 1;

  const grades: GradedTarget[] = [];
  for (const config of configs) {
    if (!config.exists) continue;
    const fileFindings = kept.filter((finding) => finding.source === config.path);
    const fileScore = riskScore(fileFindings);
    grades.push({
      source: config.path,
      grade: grade(fileScore, fileFindings.some((finding) => finding.severity === "critical")),
      score: fileScore,
      findings: fileFindings.length,
    });
    for (const server of config.servers) {
      const serverFindings = fileFindings.filter((finding) => finding.server === server.name);
      const serverScore = riskScore(serverFindings);
      const probed = deep.get(keyOf(server));
      grades.push({
        source: config.path,
        server: server.name,
        grade: grade(serverScore, serverFindings.some((finding) => finding.severity === "critical")),
        score: serverScore,
        findings: serverFindings.length,
        ...(probed?.status === "ok" ? { tools: probed.tools.length } : {}),
      });
    }
  }

  return {
    scannedAt: new Date().toISOString(),
    deepUsed: options.deep,
    configs,
    deep: [...deep.values()],
    findings: kept,
    suppressed,
    warnings,
    ...(options.baselinePath !== undefined ? { baselinePath: options.baselinePath } : {}),
    grades,
    summary,
  };
}
