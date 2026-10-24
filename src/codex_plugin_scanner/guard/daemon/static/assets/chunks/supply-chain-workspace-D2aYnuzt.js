import { j as jsxRuntimeExports, T as Tag, ea as HiMiniComputerDesktop, a0 as HiMiniCloud, s as HiMiniCheckCircle, d as HiMiniArrowPath, a4 as HiMiniExclamationTriangle, r as reactExports, ap as HiMiniWrenchScrewdriver, A as ActionButton, c as HiMiniChevronDown, ab as HiMiniExclamationCircle } from "../guard-dashboard.js";
import { r as resolveSupplyChainIssues } from "./supply-chain-issues-hFGaGr34.js";
import { r as resolveHomeProtectionStatus } from "./home-protection-module-Du65PsUR.js";
import { b as buildSupplyChainStats } from "./supply-chain-protection-stats-CJkxdP0r.js";
import { s as supplyChainFixAllIsPending, a as supplyChainFixAllNeedsCloudConnect, b as supplyChainFixAllButtonLabel } from "./supply-chain-hub-workspace-C3d9J9-5.js";
import "./feed-health-workspace-CdF42t_-.js";
function protectionTitle(status) {
  if (status === "protected") {
    return "Package installs are protected on this device";
  }
  if (status === "partial") {
    return "Protection is only partly set up";
  }
  if (status === "staged") {
    return "Finish setup in a new terminal";
  }
  if (status === "unprotected") {
    return "Package installs are not protected yet";
  }
  return "Checking package protection on this device";
}
function protectionDetail(snapshot, status) {
  const protection = snapshot.supply_chain?.package_manager_protection;
  if (status === "protected" && protection) {
    return `${protection.protected_managers.length} package tool${protection.protected_managers.length === 1 ? "" : "s"} active. Guard can block risky installs before they run.`;
  }
  if (status === "partial" && protection) {
    return `${protection.unprotected_managers.length} tool${protection.unprotected_managers.length === 1 ? "" : "s"} still open: ${protection.unprotected_managers.join(", ")}.`;
  }
  if (status === "staged") {
    return "Guard saved your shell setup. Open a new terminal or restart AI apps so the updated PATH takes effect, then refresh status here.";
  }
  if (status === "unprotected") {
    return "Turn on protection for npm, pip, and other tools in the firewall panel below.";
  }
  return "Refresh status after installing package tools on this machine.";
}
function protectionTone(status) {
  if (status === "protected") {
    return "green";
  }
  if (status === "staged") {
    return "blue";
  }
  if (status === "partial" || status === "unprotected") {
    return "attention";
  }
  return "slate";
}
function cloudLabel(snapshot) {
  const label = snapshot.cloud_state_label ?? "";
  if (snapshot.cloud_state === "paired_active") {
    return label.trim().length > 0 ? label : "Guard Cloud connected";
  }
  if (snapshot.cloud_state === "paired_waiting") {
    return label.trim().length > 0 ? label : "Pairing in progress";
  }
  return label.trim().length > 0 ? label : "On this device only";
}
function resolveSupplyChainWorkspaceHero(snapshot, options) {
  const protectionStatus = resolveHomeProtectionStatus(snapshot);
  const stats = buildSupplyChainStats(snapshot);
  const preventedLabel = stats.preventedInstalls > 0 ? `${stats.preventedInstalls} blocked install${stats.preventedInstalls === 1 ? "" : "s"}` : "No blocked installs yet";
  const stagedGuidance = protectionStatus === "staged" ? protectionDetail(snapshot, protectionStatus) : null;
  const openIssueCount = options?.openIssueCount ?? 0;
  if (openIssueCount > 0) {
    const issueSummary = `${openIssueCount} setup step${openIssueCount === 1 ? "" : "s"} ${openIssueCount === 1 ? "needs" : "need"} attention on this device.`;
    return {
      cloudMode: snapshot.cloud_state,
      cloudLabel: cloudLabel(snapshot),
      protectionStatus,
      title: "Work through the steps below",
      detail: stagedGuidance ? `${issueSummary} ${stagedGuidance}` : issueSummary,
      stagedGuidance,
      tone: protectionTone(protectionStatus),
      statLine: `${stats.protectedManagers} protected · ${stats.unprotectedManagers} open · ${preventedLabel}`
    };
  }
  return {
    cloudMode: snapshot.cloud_state,
    cloudLabel: cloudLabel(snapshot),
    protectionStatus,
    title: protectionTitle(protectionStatus),
    detail: protectionDetail(snapshot, protectionStatus),
    stagedGuidance,
    tone: protectionTone(protectionStatus),
    statLine: `${stats.protectedManagers} protected · ${stats.unprotectedManagers} open · ${preventedLabel}`
  };
}
function supplyChainCloudTagTone(mode) {
  if (mode === "paired_active") {
    return "green";
  }
  if (mode === "paired_waiting") {
    return "blue";
  }
  return "attention";
}
function heroSurfaceClass(tone) {
  if (tone === "green") {
    return "border-brand-green/20 bg-brand-green/[0.04]";
  }
  if (tone === "blue") {
    return "border-brand-blue/20 bg-brand-blue/[0.04]";
  }
  if (tone === "attention") {
    return "border-brand-attention/20 bg-brand-attention/[0.04]";
  }
  return "border-slate-200 bg-slate-50/80";
}
function heroIcon(hero) {
  if (hero.protectionStatus === "protected") {
    return HiMiniCheckCircle;
  }
  if (hero.protectionStatus === "staged") {
    return HiMiniArrowPath;
  }
  if (hero.protectionStatus === "partial" || hero.protectionStatus === "unprotected") {
    return HiMiniExclamationTriangle;
  }
  return HiMiniComputerDesktop;
}
function heroIconClass(tone) {
  if (tone === "green") {
    return "text-brand-green";
  }
  if (tone === "blue") {
    return "text-brand-blue";
  }
  if (tone === "attention") {
    return "text-brand-attention";
  }
  return "text-slate-500";
}
function SupplyChainWorkspaceHero({ hero, compact = false }) {
  const Icon = heroIcon(hero);
  const titleClass = "text-brand-dark";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "section",
    {
      className: `rounded-2xl border px-4 py-4 sm:px-5 sm:py-5 ${heroSurfaceClass(hero.tone)}`,
      "aria-label": "Supply chain protection status",
      "data-testid": "supply-chain-workspace-hero",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs(Tag, { tone: supplyChainCloudTagTone(hero.cloudMode), children: [
            hero.cloudMode === "local_only" ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniComputerDesktop, { className: "mr-1 inline h-3.5 w-3.5", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCloud, { className: "mr-1 inline h-3.5 w-3.5", "aria-hidden": "true" }),
            hero.cloudLabel
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs text-slate-500", children: hero.statLine })
        ] }),
        !compact ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 flex items-start gap-2.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { className: `mt-0.5 h-5 w-5 shrink-0 ${heroIconClass(hero.tone)}`, "aria-hidden": "true" }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: `text-lg font-semibold tracking-tight ${titleClass}`, children: hero.title }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 max-w-2xl text-sm leading-relaxed text-slate-600", children: hero.detail })
          ] })
        ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-slate-600", children: hero.detail })
      ]
    }
  );
}
function recoverySummary(issueCount) {
  return `${issueCount} issue${issueCount === 1 ? "" : "s"} to resolve. Check Cloud access, approve device changes once, then restore package protection.`;
}
function SupplyChainRecovery({
  issues,
  state,
  onFixAll,
  guidance = null
}) {
  const [detailsOpen, setDetailsOpen] = reactExports.useState(false);
  const handleDetailsToggle = reactExports.useCallback(() => {
    setDetailsOpen((open) => !open);
  }, []);
  const pending = supplyChainFixAllIsPending(state.phase);
  const showResult = state.message !== null;
  const remainingSteps = state.remainingSteps ?? [];
  const failures = [...new Set(state.failedSteps)].filter((message) => message !== state.message);
  const needsCloudConnect = supplyChainFixAllNeedsCloudConnect(state);
  const isHardFailure = state.phase === "error" || state.phase === "incomplete" && state.failedSteps.length > 0;
  const buttonLabel = supplyChainFixAllButtonLabel(
    state.phase,
    state.remainingAction ?? null,
    state.failedSteps.length
  );
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "section",
    {
      className: "border-y border-brand-attention/20 bg-brand-attention/[0.04] px-4 py-4 sm:px-5",
      "aria-label": "Supply-chain recovery",
      "data-testid": "supply-chain-recovery",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                HiMiniWrenchScrewdriver,
                {
                  className: "h-4 w-4 shrink-0 text-brand-attention",
                  "aria-hidden": "true"
                }
              ),
              /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-sm font-semibold text-brand-dark", children: "Restore supply-chain protection" })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 max-w-3xl text-sm text-slate-600", children: recoverySummary(issues.length) }),
            guidance ? /* @__PURE__ */ jsxRuntimeExports.jsx(
              "p",
              {
                className: "mt-2 max-w-3xl text-sm font-medium text-brand-primary",
                "data-testid": "supply-chain-restart-guidance",
                children: guidance
              }
            ) : null
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: onFixAll, disabled: pending, "aria-busy": pending, children: buttonLabel })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: showResult ? "mt-3" : "", "aria-live": "polite", children: showResult ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs(
            "p",
            {
              className: `flex items-start gap-2 text-sm ${isHardFailure ? "text-red-600" : "text-slate-600"}`,
              children: [
                state.phase === "success" || needsCloudConnect ? /* @__PURE__ */ jsxRuntimeExports.jsx(
                  HiMiniCheckCircle,
                  {
                    className: "mt-0.5 h-4 w-4 shrink-0 text-emerald-500",
                    "aria-hidden": "true"
                  }
                ) : null,
                state.message
              ]
            }
          ),
          failures.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-2 space-y-1 text-xs text-red-600", children: failures.map((failure, index) => /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: failure }, `failed:${index}:${failure}`)) }) : null,
          state.phase === "access_required" ? /* @__PURE__ */ jsxRuntimeExports.jsx("a", { className: "mt-2 inline-block text-sm font-medium text-brand-primary underline underline-offset-4 focus-visible:outline focus-visible:outline-2", href: "https://hol.org/guard/pricing", target: "_blank", rel: "noopener noreferrer", children: "Review Cloud plan" }) : null,
          remainingSteps.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-2 space-y-1 text-xs font-medium text-brand-primary", children: remainingSteps.map((remaining, index) => /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: remaining }, `remaining:${index}:${remaining}`)) }) : null
        ] }) : null }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "button",
          {
            type: "button",
            onClick: handleDetailsToggle,
            "aria-expanded": detailsOpen,
            className: "mt-3 inline-flex items-center gap-1 text-xs font-medium text-brand-primary hover:underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2",
            children: [
              "View issue details",
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                HiMiniChevronDown,
                {
                  className: `h-4 w-4 transition-transform ${detailsOpen ? "rotate-180" : ""}`,
                  "aria-hidden": "true"
                }
              )
            ]
          }
        ),
        detailsOpen ? /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-2 border-t border-brand-attention/10", children: issues.map((issue) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "li",
          {
            className: "flex items-start gap-2 border-t border-brand-attention/10 py-3 first:border-t-0",
            children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                HiMiniExclamationCircle,
                {
                  className: "mt-0.5 h-3.5 w-3.5 shrink-0 text-brand-attention",
                  "aria-hidden": "true"
                }
              ),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-xs text-slate-600", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { className: "block font-semibold text-brand-dark", children: issue.title }),
                issue.detail
              ] })
            ]
          },
          issue.id
        )) }) : null
      ]
    }
  );
}
function SupplyChainWorkspace({ snapshot, fixAllState, onFixAll }) {
  const supplyChainIssues = reactExports.useMemo(() => resolveSupplyChainIssues(snapshot), [snapshot]);
  const workspaceHero = reactExports.useMemo(
    () => resolveSupplyChainWorkspaceHero(snapshot, { openIssueCount: supplyChainIssues.length }),
    [snapshot, supplyChainIssues.length]
  );
  return supplyChainIssues.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(
    SupplyChainRecovery,
    {
      issues: supplyChainIssues,
      state: fixAllState,
      onFixAll,
      guidance: workspaceHero.stagedGuidance
    }
  ) : /* @__PURE__ */ jsxRuntimeExports.jsx(SupplyChainWorkspaceHero, { hero: workspaceHero });
}
export {
  SupplyChainWorkspace,
  buildSupplyChainStats
};
