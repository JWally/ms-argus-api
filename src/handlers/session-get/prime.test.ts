import { describe, it, expect, vi, beforeEach } from "vitest";

const primePublicKey = vi.fn();
const fetchIntegrityResultsByComposite = vi.fn();
const buildMerchantResponse = vi.fn();

vi.mock("../../helpers/token-verifier", () => ({
  primePublicKey: (...a: unknown[]) => primePublicKey(...a),
}));
vi.mock("./session-ops", () => ({
  fetchIntegrityResultsByComposite: (...a: unknown[]) =>
    fetchIntegrityResultsByComposite(...a),
}));
vi.mock("../../helpers/merchant-projection", () => ({
  buildMerchantResponse: (...a: unknown[]) => buildMerchantResponse(...a),
}));

import { primeSessionGet } from "./prime";

const deps = () => ({
  dynamodb: {} as never,
  integrityResultsTable: "t",
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() } as never,
  metrics: { addMetric: vi.fn() } as never,
  ssmPubkeyPath: "/argus/pubkey",
});

beforeEach(() => {
  vi.clearAllMocks();
  primePublicKey.mockResolvedValue(undefined);
  fetchIntegrityResultsByComposite.mockResolvedValue(undefined);
  buildMerchantResponse.mockReturnValue({});
});

describe("primeSessionGet", () => {
  it("warms all three: pubkey, DDB read, and the projection", async () => {
    await primeSessionGet(deps());
    expect(primePublicKey).toHaveBeenCalledWith("/argus/pubkey");
    expect(fetchIntegrityResultsByComposite).toHaveBeenCalledTimes(1);
    expect(buildMerchantResponse).toHaveBeenCalledTimes(1);
  });

  it("is fail-open: a rejected pubkey/DDB leg never throws", async () => {
    primePublicKey.mockRejectedValue(new Error("ssm down"));
    fetchIntegrityResultsByComposite.mockRejectedValue(new Error("ddb down"));
    await expect(primeSessionGet(deps())).resolves.toBeUndefined();
    // projection still ran despite the other legs failing
    expect(buildMerchantResponse).toHaveBeenCalledTimes(1);
  });

  it("skips the pubkey leg when no SSM path is configured", async () => {
    await primeSessionGet({ ...deps(), ssmPubkeyPath: undefined });
    expect(primePublicKey).not.toHaveBeenCalled();
    expect(fetchIntegrityResultsByComposite).toHaveBeenCalledTimes(1);
  });
});
