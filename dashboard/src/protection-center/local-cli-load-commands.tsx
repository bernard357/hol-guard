import { useCallback, useEffect, useRef, useState } from "react";

import { DiscoveryFailure } from "../discovery-failure";
import { LocalCliApiError, refreshMcpInventory, type LocalCliItem } from "../local-cli-api";

/** Job failures whose shared wording names connectors; a command-line tool gets its own. */
const CLI_FAILURE_COPY: Record<string, string> = {
  catalog_limit_reached: "This tool lists more commands than Guard can keep. Commands and choices already saved were kept.",
  discovery_failed: "Loading stopped on an unexpected error. Commands and choices already saved were kept. Try again; if it keeps failing, restart Guard.",
};

export function loadCommandsFailureMessage(caught: unknown): string {
  if (caught instanceof DiscoveryFailure) return CLI_FAILURE_COPY[caught.code] ?? caught.message;
  if (caught instanceof LocalCliApiError) return caught.message;
  return "Guard could not load this tool's commands. Try again.";
}

/**
 * Reads a seen-in-use tool's --help on request, so its commands can be set
 * to Allow or Block one by one. The daemon only runs a program it finds on
 * PATH by name that is still the one it recorded; scripts are left to the
 * Add custom extension flow, which takes their full path.
 */
export function LocalCliLoadCommands(props: {
  item: LocalCliItem;
  disabled: boolean;
  onLoaded: () => Promise<void>;
}) {
  const { item, onLoaded } = props;
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const controllerRef = useRef<AbortController | null>(null);
  useEffect(() => () => controllerRef.current?.abort(), []);
  useEffect(() => {
    setError(null);
    setLoaded(false);
  }, [item.cli_id]);

  const load = useCallback(async () => {
    const controller = new AbortController();
    controllerRef.current = controller;
    setBusy(true);
    setError(null);
    setLoaded(false);
    try {
      await refreshMcpInventory(item.cli_id, controller.signal);
      if (controller.signal.aborted) return;
      await onLoaded();
      setLoaded(true);
    } catch (caught) {
      if (!controller.signal.aborted) setError(loadCommandsFailureMessage(caught));
    } finally {
      setBusy(false);
      if (controllerRef.current === controller) controllerRef.current = null;
    }
  }, [item.cli_id, onLoaded]);

  if (item.kind !== "executable") {
    return (
      <p className="mt-3 max-w-2xl text-sm leading-6 text-brand-dark/75">
        Guard does not run scripts on its own. To list this script&apos;s commands, find it again in Add custom
        extension using its full path.
      </p>
    );
  }
  const hasCommands = item.commands.length > 0;
  return (
    <div className="mt-3 max-w-2xl" aria-busy={busy}>
      <p className="text-sm leading-6 text-brand-dark/75">
        Guard runs <code className="rounded-md bg-slate-100 px-1.5 py-0.5 font-mono text-xs font-semibold text-brand-dark">{item.name} --help</code> from an empty temporary
        folder, then the same for each command it lists. A program that ignores --help may do its normal work
        instead, so load commands only for tools you trust. Loading adds commands and never changes a choice you
        already made.
      </p>
      <div className="mt-3 flex flex-wrap items-center gap-3">
        <button
          type="button"
          onClick={() => void load()}
          disabled={props.disabled || busy}
          className="inline-flex min-h-11 items-center rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark disabled:cursor-wait disabled:opacity-50"
        >
          {busy ? "Loading commands…" : hasCommands ? "Check for new commands" : "Load commands"}
        </button>
        {busy ? (
          <button
            type="button"
            onClick={() => controllerRef.current?.abort()}
            className="min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark"
          >
            Cancel
          </button>
        ) : null}
      </div>
      {error ? <p role="alert" className="mt-3 text-sm leading-6 text-red-700">{error}</p> : null}
      {loaded && !hasCommands ? (
        <p role="status" className="mt-3 text-sm leading-6 text-brand-dark/75">
          {item.name} --help did not list any commands. Guard keeps reviewing it as one tool.
        </p>
      ) : null}
    </div>
  );
}
