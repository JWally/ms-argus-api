import { describe, expect, it } from "vitest";
import type { IntegrityResultsData } from "./payload-schema";
import { deriveWorkerScopeEvidence } from "./worker-scope-evidence";

type ScopeValues = {
  hardwareConcurrency: number;
  deviceMemory: number;
  languages: string;
};

const MAIN: ScopeValues = {
  hardwareConcurrency: 12,
  deviceMemory: 32,
  languages: "en-US,en",
};

function integrity(input: {
  main?: ScopeValues;
  web?: ScopeValues;
  shared?: ScopeValues;
  divergences?: Array<{
    field: string;
    main: unknown;
    web: unknown;
    shared: unknown;
  }>;
  brave?: boolean;
}): IntegrityResultsData {
  const main = input.main ?? MAIN;
  const web = input.web ?? MAIN;
  const shared = input.shared ?? MAIN;
  const divergences = input.divergences ?? [];
  const brands = input.brave
    ? [{ brand: "Chromium" }, { brand: "Brave" }]
    : [{ brand: "Chromium" }];
  const withMainBrands = (scope: ScopeValues) => ({
    ...scope,
    userAgentData: { brands },
  });
  const withWorkerBrands = (scope: ScopeValues) => ({
    ...scope,
    userAgentData: { brands: input.brave ? ["Brave"] : ["Chromium"] },
  });
  return {
    session_id: "scan-1",
    device: {
      shielding: {
        privacy: input.brave ? "Brave" : "Chromium",
        engine: "Blink",
      },
      workerScope: {
        scopes: {
          main: withMainBrands(main),
          web: withWorkerBrands(web),
          shared: withWorkerBrands(shared),
        },
      },
    },
    analysis: {
      worker: {
        lied: divergences.length > 0,
        divergences,
        signals: [],
      },
    },
  } as unknown as IntegrityResultsData;
}

describe("deriveWorkerScopeEvidence", () => {
  it("matches the normal Brave host consensus to the iframe main/web consensus", () => {
    const host = deriveWorkerScopeEvidence(integrity({ brave: true }), 0);
    const iframe = deriveWorkerScopeEvidence(
      integrity({
        brave: true,
        shared: {
          hardwareConcurrency: 5,
          deviceMemory: 16,
          languages: "en-US",
        },
        divergences: [
          { field: "hardwareConcurrency", main: 12, web: 12, shared: 5 },
          { field: "deviceMemory", main: 32, web: 32, shared: 16 },
          {
            field: "languages",
            main: "en-US,en",
            web: "en-US,en",
            shared: "en-US",
          },
        ],
      }),
      0,
    );

    expect(host).toMatchObject({
      all_scopes_consistent: true,
      shared_partition_candidate: false,
      brave_detected: true,
      device_tampering_without_worker: 0,
    });
    expect(iframe).toMatchObject({
      all_scopes_consistent: false,
      shared_partition_candidate: true,
      brave_detected: true,
      device_tampering_without_worker: 0,
    });
    expect(host.main_web_consensus_id).toBeTruthy();
    expect(iframe.main_web_consensus_id).toBe(host.main_web_consensus_id);
  });

  it("matches the private Brave shape with shared-only compute and memory changes", () => {
    const privateMain = { ...MAIN, languages: "en-US" };
    const host = deriveWorkerScopeEvidence(
      integrity({
        brave: true,
        main: privateMain,
        web: privateMain,
        shared: privateMain,
      }),
      0,
    );
    const iframe = deriveWorkerScopeEvidence(
      integrity({
        brave: true,
        main: privateMain,
        web: privateMain,
        shared: {
          hardwareConcurrency: 10,
          deviceMemory: 16,
          languages: "en-US",
        },
        divergences: [
          { field: "hardwareConcurrency", main: 12, web: 12, shared: 10 },
          { field: "deviceMemory", main: 32, web: 32, shared: 16 },
        ],
      }),
      0,
    );

    expect(host.all_scopes_consistent).toBe(true);
    expect(iframe.shared_partition_candidate).toBe(true);
    expect(iframe.main_web_consensus_id).toBe(host.main_web_consensus_id);
  });

  it.each([
    {
      name: "user agent",
      field: "userAgent",
      main: "ua-main",
      web: "ua-web",
      shared: "ua-shared",
    },
    {
      name: "platform",
      field: "platform",
      main: "Linux",
      web: "Win32",
      shared: "Linux",
    },
    {
      name: "renderer",
      field: "webglRenderer",
      main: "gpu-a",
      web: "gpu-a",
      shared: "gpu-b",
    },
  ])(
    "rejects a $name divergence from the narrow candidate",
    ({ field, main, web, shared }) => {
      const evidence = deriveWorkerScopeEvidence(
        integrity({
          brave: true,
          divergences: [{ field, main, web, shared }],
        }),
        0,
      );

      expect(evidence.shared_partition_candidate).toBe(false);
    },
  );

  it("requires positive Brave detection and preserves other tampering", () => {
    const evidence = deriveWorkerScopeEvidence(
      integrity({
        divergences: [
          { field: "hardwareConcurrency", main: 12, web: 12, shared: 5 },
        ],
      }),
      60,
    );

    expect(evidence.brave_detected).toBe(false);
    expect(evidence.device_tampering_without_worker).toBe(60);
  });
});
