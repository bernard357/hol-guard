import { Tag, type TagTone } from "./approval-center-primitives";
import type { WorkspaceFinding } from "./workspace-findings-api";

export function Cell(props: { label: string; wide?: boolean; children: React.ReactNode }) {
  return (
    <td className={`min-w-0 md:px-3 md:py-2.5 ${props.wide ? "col-span-2 md:col-span-1" : ""}`}>
      <span className="block text-xs font-semibold text-slate-500 md:hidden">{props.label}</span>
      {props.children}
    </td>
  );
}

function secretLines(finding: WorkspaceFinding): string {
  const lines = finding.lines.length > 0 ? finding.lines : finding.line !== null ? [finding.line] : [];
  return lines.length > 0 ? `:${lines.join(", ")}` : "";
}

export function SecretFindingsTable({ findings }: { findings: WorkspaceFinding[] }) {
  return (
    <div className="overflow-hidden rounded-xl border border-slate-200">
      <table className="w-full text-left text-sm">
        <caption className="sr-only">Possible secrets in files</caption>
        <thead className="hidden bg-slate-50 text-xs font-semibold text-slate-600 md:table-header-group">
          <tr>
            <th scope="col" className="px-3 py-2">Rule</th>
            <th scope="col" className="px-3 py-2">Location</th>
            <th scope="col" className="px-3 py-2">Severity</th>
            <th scope="col" className="px-3 py-2">Status</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {findings.map((finding) => (
            <tr key={finding.findingId} className="grid grid-cols-2 gap-x-3 gap-y-2 px-3 py-3 md:table-row md:p-0">
              <Cell label="Rule">
                <span className="break-all font-mono text-xs text-slate-700">{finding.ruleIds.join(", ")}</span>
              </Cell>
              <Cell label="Location" wide>
                <span className="break-all font-mono text-xs text-slate-700">
                  {finding.path}
                  {secretLines(finding)}
                </span>
              </Cell>
              <Cell label="Severity"><span className="capitalize text-slate-700">{finding.severity}</span></Cell>
              <Cell label="Status"><Tag tone="slate">Not verified</Tag></Cell>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

const CONFIDENCE_LABELS: Record<string, string> = { strong: "Strong signal", likely: "Likely", weak: "Weak signal" };

/**
 * Agent skills whose instructions match a skill content rule. Each row shows the
 * rule's own wording, never text from the skill, and is a warning only.
 */
export function SkillFindingsTable({ findings }: { findings: WorkspaceFinding[] }) {
  return (
    <div className="overflow-hidden rounded-xl border border-slate-200">
      <table className="w-full text-left text-sm">
        <caption className="sr-only">Agent skills with risky instructions</caption>
        <thead className="hidden bg-slate-50 text-xs font-semibold text-slate-600 md:table-header-group">
          <tr>
            <th scope="col" className="px-3 py-2">Skill</th>
            <th scope="col" className="px-3 py-2">Check</th>
            <th scope="col" className="px-3 py-2">Severity</th>
            <th scope="col" className="px-3 py-2">Status</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {findings.map((finding) => (
            <tr key={finding.findingId} className="grid grid-cols-2 gap-x-3 gap-y-2 px-3 py-3 md:table-row md:p-0">
              <Cell label="Skill" wide>
                <span className="break-all font-mono text-xs text-slate-700">{finding.path}</span>
              </Cell>
              <Cell label="Check" wide>
                <span className="block font-semibold text-brand-dark">{finding.skill?.title}</span>
                <span className="mt-0.5 block text-xs text-slate-600">{finding.skill?.reason}</span>
                {finding.skill?.falsePositiveHint && (
                  <span className="mt-0.5 block text-xs text-slate-500">{finding.skill.falsePositiveHint}</span>
                )}
                <span className="mt-1 block break-all font-mono text-xs text-slate-500">{finding.ruleIds.join(", ")}</span>
              </Cell>
              <Cell label="Severity">
                <span className="capitalize text-slate-700">{finding.severity}</span>
                {finding.skill && (
                  <span className="block text-xs text-slate-500">
                    {CONFIDENCE_LABELS[finding.skill.confidence] ?? finding.skill.confidence}
                  </span>
                )}
              </Cell>
              <Cell label="Status"><Tag tone="amber">Warning</Tag></Cell>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

const RUNTIME_VERDICTS: Record<string, { label: string; tone: TagTone }> = {
  affected: { label: "Affected version", tone: "attention" },
  restart_required: { label: "Restart needed", tone: "amber" },
  fix_unverified: { label: "Fix not verified", tone: "amber" },
};

/** Executables the workspace's tools would launch that match an advisory. Observation only: Guard offers no fix. */
export function RuntimeFindingsTable({ findings }: { findings: WorkspaceFinding[] }) {
  return (
    <div className="overflow-hidden rounded-xl border border-slate-200">
      <table className="w-full text-left text-sm">
        <caption className="sr-only">Runtimes launched by this workspace's tools that match an advisory</caption>
        <thead className="hidden bg-slate-50 text-xs font-semibold text-slate-600 md:table-header-group">
          <tr>
            <th scope="col" className="px-3 py-2">Runtime</th>
            <th scope="col" className="px-3 py-2">Executable</th>
            <th scope="col" className="px-3 py-2">Status</th>
            <th scope="col" className="px-3 py-2">Severity</th>
            <th scope="col" className="px-3 py-2">Advisories</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {findings.map((finding) => {
            const verdict = RUNTIME_VERDICTS[finding.ruleIds[0] ?? ""] ?? { label: "Matches an advisory", tone: "amber" as TagTone };
            return (
              <tr key={finding.findingId} className="grid grid-cols-2 gap-x-3 gap-y-2 px-3 py-3 md:table-row md:p-0">
                <Cell label="Runtime" wide>
                  <span className="font-semibold capitalize text-brand-dark">{finding.runtime?.family}</span>
                  <span className="ml-2 font-mono text-xs text-slate-500">{finding.runtime?.version ?? "version unknown"}</span>
                </Cell>
                <Cell label="Executable" wide>
                  <span className="break-all font-mono text-xs text-slate-700">{finding.path}</span>
                </Cell>
                <Cell label="Status">
                  <span className="flex flex-wrap gap-1">
                    <Tag tone={verdict.tone}>{verdict.label}</Tag>
                    {finding.runtime?.knownExploited && <Tag tone="red">Known exploited</Tag>}
                  </span>
                </Cell>
                <Cell label="Severity"><span className="capitalize text-slate-700">{finding.severity}</span></Cell>
                <Cell label="Advisories" wide>
                  <span className="break-all font-mono text-xs text-slate-700">{finding.advisoryIds.join(", ")}</span>
                  {finding.runtime?.title && <span className="mt-0.5 block text-xs text-slate-500">{finding.runtime.title}</span>}
                </Cell>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
