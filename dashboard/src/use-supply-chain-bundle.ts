import { useEffect, useState } from "react";
import { fetchSupplyChainBundle } from "./guard-api";
import type { SupplyChainBundleLoad } from "./supply-chain-intel-freshness";

/**
 * Reads the signed advisory bundle Guard has cached. Pass a `refreshKey` that
 * changes when a sync lands so the bundle is read again; a refresh keeps the
 * previous result on screen instead of flashing a loading state.
 */
export function useSupplyChainBundle(refreshKey = ""): SupplyChainBundleLoad {
  const [load, setLoad] = useState<SupplyChainBundleLoad>({ phase: "loading" });

  useEffect(() => {
    let cancelled = false;
    fetchSupplyChainBundle()
      .then((bundle) => {
        if (!cancelled) setLoad({ phase: "ready", bundle });
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        const message = error instanceof Error ? error.message : "Failed to load";
        setLoad((previous) => (previous.phase === "ready" ? previous : { phase: "error", message }));
      });
    return () => {
      cancelled = true;
    };
  }, [refreshKey]);

  return load;
}
