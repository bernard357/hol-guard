export type SupplyChainSyncFailureKind = "unverified_bundle" | "unreachable" | "approval_step" | "generic";

export type SupplyChainSyncFailure = {
  kind: SupplyChainSyncFailureKind;
  title: string;
  summary: string;
  nextStep: string;
  technicalDetail: string;
};

const UNVERIFIED_BUNDLE = /payload\s*hash|canonical payload|signature|verification key|bundle (?:is )?(?:invalid|unverified)/i;
const UNREACHABLE = /lost connection|failed to fetch|network|unreachable|timed out|timeout|temporarily unavailable|could not be reached/i;

/**
 * Turn a raw sync failure into what happened and what to do next. The raw text
 * stays available as technical detail so support can still see the exact cause.
 * Verification failures are never offered as something to skip: the bundle was
 * not installed, and the step is to update Guard and sync again.
 */
export function describeSupplyChainSyncFailure(
  message: string,
  options?: { approvalStep?: boolean },
): SupplyChainSyncFailure {
  const technicalDetail = message.trim();
  if (UNVERIFIED_BUNDLE.test(technicalDetail)) {
    return {
      kind: "unverified_bundle",
      title: "Guard could not verify the downloaded intel",
      summary:
        "The bundle did not match its signed fingerprint, so Guard did not install it. Intel already on this device is unchanged.",
      nextStep: "Update Guard to the latest version, then sync again. If it still fails, share the technical detail with support.",
      technicalDetail,
    };
  }
  if (UNREACHABLE.test(technicalDetail)) {
    return {
      kind: "unreachable",
      title: "Guard could not finish the sync",
      summary: "Guard lost contact with the intel service or the local daemon before the bundle arrived.",
      nextStep: "Check your connection and that Guard is still running, then sync again.",
      technicalDetail,
    };
  }
  if (options?.approvalStep === true) {
    return {
      kind: "approval_step",
      title: "The sync did not finish",
      summary: technicalDetail === "" ? "Guard stopped before the sync completed." : technicalDetail,
      nextStep: "If your approval proof was rejected, enter it again and sync. Otherwise go back and review the steps.",
      technicalDetail: "",
    };
  }
  return {
    kind: "generic",
    title: "The sync did not finish",
    summary: technicalDetail === "" ? "Guard stopped before the sync completed." : technicalDetail,
    nextStep: "Try again. If it keeps failing, update Guard and sync once more.",
    technicalDetail: "",
  };
}
