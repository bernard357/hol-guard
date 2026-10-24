import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import { ApprovalProofInline } from "./approval-proof-inline";
import { describeSupplyChainSyncFailure } from "./supply-chain-audit-failure";
import { SupplyChainAuditFailureNotice } from "./supply-chain-audit-failure-notice";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

const HASH_MISMATCH =
  "Guard supply-chain bundle sync failed: Bundle payloadHash does not match the canonical payload";

const mismatch = describeSupplyChainSyncFailure(HASH_MISMATCH, { approvalStep: true });
assert(mismatch.kind === "unverified_bundle", "payload hash mismatch is an unverified bundle");
assert(mismatch.nextStep.includes("Update Guard"), "payload hash mismatch tells the user to update Guard");
assert(mismatch.summary.includes("did not install it"), "payload hash mismatch says nothing was installed");
assert(mismatch.technicalDetail === HASH_MISMATCH, "payload hash mismatch keeps the exact technical text");
assert(!/skip|ignore|override|bypass|anyway/i.test(`${mismatch.summary} ${mismatch.nextStep}`), "verification is never offered as skippable");

const signature = describeSupplyChainSyncFailure("Bundle signature verification failed");
assert(signature.kind === "unverified_bundle", "signature failures are unverified bundles");

const offline = describeSupplyChainSyncFailure(
  "Guard lost connection while syncing supply-chain intel. Confirm the local daemon is still running, then try again.",
);
assert(offline.kind === "unreachable", "connection loss reads as unreachable");
assert(offline.nextStep.includes("connection"), "connection loss tells the user to check the connection");

const rejected = describeSupplyChainSyncFailure("Approval password is incorrect.", { approvalStep: true });
assert(rejected.kind === "approval_step", "approval step failures keep their own kind");
assert(rejected.summary === "Approval password is incorrect.", "approval step failures keep the message");
assert(rejected.nextStep.includes("enter it again"), "approval step failures tell the user to re-enter proof");

const generic = describeSupplyChainSyncFailure("Sync failed.");
assert(generic.kind === "generic" && generic.nextStep.startsWith("Try again"), "other failures say to try again");
assert(describeSupplyChainSyncFailure("   ").summary.length > 0, "an empty message still explains the failure");

const noticeMarkup = renderToStaticMarkup(<SupplyChainAuditFailureNotice message={HASH_MISMATCH} />);
assert(noticeMarkup.includes('role="alert"'), "failure notice is announced as an alert");
assert(noticeMarkup.includes("Guard could not verify the downloaded intel"), "failure notice names what happened");
assert(noticeMarkup.includes("Update Guard to the latest version"), "failure notice names the next step");
assert(noticeMarkup.includes("Bundle payloadHash does not match the canonical payload"), "failure notice keeps the technical detail");
assert(!/class="[^"]*\btext-brand-attention(?![-\w])/.test(noticeMarkup), "failure notice never sets text in the pale attention hue");
assert(noticeMarkup.includes("text-brand-attention-text"), "failure notice uses the accessible attention text tone");
assert(noticeMarkup.includes("bg-brand-attention-bg"), "failure notice uses the brand attention surface");
assert(!/yellow|amber|orange|red-/.test(noticeMarkup), "failure notice stays in the brand palette");

const noop = () => undefined;
const approvalMarkup = renderToStaticMarkup(
  <ApprovalProofInline
    approvalGate={{
      enabled: true,
      configured: true,
      cooldown_seconds: 0,
      cooldown_active: false,
      cooldown_expires_at: null,
      locked_until: null,
      fail_closed: true,
      strict_all_decisions: false,
    }}
    approvalPassword=""
    approvalTotpCode=""
    error={<SupplyChainAuditFailureNotice message={HASH_MISMATCH} approvalStep />}
    submitLabel="Sync supply-chain intel"
    submitBusy={false}
    onApprovalPasswordChange={noop}
    onApprovalTotpCodeChange={noop}
    onSubmit={noop}
    onBack={noop}
  />,
);
assert(approvalMarkup.includes("Update Guard to the latest version"), "approval step shows the next step");
assert(approvalMarkup.includes("Sync supply-chain intel"), "approval step keeps its submit action");
assert(approvalMarkup.includes("Go back"), "approval step keeps its way back");

const quietMarkup = renderToStaticMarkup(
  <ApprovalProofInline
    approvalGate={null}
    approvalPassword=""
    approvalTotpCode=""
    error={null}
    submitLabel="Sync supply-chain intel"
    submitBusy={false}
    onApprovalPasswordChange={noop}
    onApprovalTotpCodeChange={noop}
    onSubmit={noop}
    onBack={noop}
  />,
);
assert(!quietMarkup.includes('role="alert"'), "no alert renders without an error");

const modalSource = readFileSync(new URL("./supply-chain-audit-recovery-modal.tsx", import.meta.url), "utf8");
const proofSource = readFileSync(new URL("./approval-proof-inline.tsx", import.meta.url), "utf8");
assert(
  (modalSource.match(/<SupplyChainAuditFailureNotice /g) ?? []).length === 2,
  "both modal steps render errors through the failure notice",
);
assert(!/text-brand-attention"/.test(modalSource) && !/text-brand-attention"/.test(proofSource), "modal text never uses the pale attention hue");

console.log("supply-chain-audit-failure.test.tsx: all assertions passed");
