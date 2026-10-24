import { TrackedExternalButton } from "./tracked-action-button";
import { MachineFigure } from "./machine-figure";
import { ABOUT_HERO_BODY, ABOUT_HERO_TITLE } from "../about-content";
import type { AboutRuntimeSummary } from "../about-types";

export function AboutHero({
  runtimeSummary,
}: {
  runtimeSummary: AboutRuntimeSummary | null;
}) {
  // The actions follow the figure in source order so phones reach the diagram
  // first; wide screens lift them beside the title. The figure holds no
  // focusable elements, so keyboard order is the same either way.
  return (
    <div className="grid gap-x-8 gap-y-6 lg:grid-cols-[minmax(0,1fr)_auto]">
      <div className="max-w-[60ch]">
        <h1
          id="about-hero-heading"
          className="text-3xl font-bold tracking-[-0.03em] text-balance text-brand-dark sm:text-4xl"
        >
          {ABOUT_HERO_TITLE}
        </h1>
        <p className="mt-3 text-base leading-7 text-brand-dark/75 sm:text-lg sm:leading-8">
          {ABOUT_HERO_BODY}
        </p>
      </div>
      <div className="lg:col-span-2 lg:row-start-2 lg:mt-2">
        <MachineFigure runtimeSummary={runtimeSummary} />
      </div>
      <div className="flex shrink-0 flex-wrap gap-3 lg:col-start-2 lg:row-start-1 lg:self-end">
        <TrackedExternalButton linkId="guard_docs" href="https://hol.org/guard/docs" variant="primary">
          Read Guard docs
        </TrackedExternalButton>
        <TrackedExternalButton linkId="hol_guard_source" href="https://github.com/hashgraph-online/hol-guard" variant="outline">
          View source
        </TrackedExternalButton>
      </div>
    </div>
  );
}
