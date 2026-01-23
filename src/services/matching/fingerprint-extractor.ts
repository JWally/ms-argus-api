import type { ArgusPayload } from "../../helpers/payload-schema";
import type { Fingerprint } from "../../types";

/**
 * Extract flat fingerprint fields from V3 payload.
 * Pure transformation: no AWS calls, no side effects.
 */
export function extractFingerprint(payload: ArgusPayload): Fingerprint {
  const { hashes, device, sigint, identifiers } = payload;

  const fingerprint: Fingerprint = {
    stable_hash: hashes.stable,
    fuzzy_hash: hashes.fuzzy,
  };

  // Identifiers
  if (identifiers.evercookie_id) {
    fingerprint.evercookie_id = identifiers.evercookie_id;
  }
  if (identifiers.public_key) {
    fingerprint.public_key = identifiers.public_key;
  }

  // workerScope component (browser/device info)
  const workerScope = device.workerScope;
  if (workerScope) {
    if (typeof workerScope.userAgent === "string") {
      fingerprint.user_agent = workerScope.userAgent;
    }
    if (typeof workerScope.hardwareConcurrency === "number") {
      fingerprint.hardware_concurrency = workerScope.hardwareConcurrency;
    }
    if (typeof workerScope.deviceMemory === "number") {
      fingerprint.device_memory = workerScope.deviceMemory;
    }
    if (typeof workerScope.webglRenderer === "string") {
      fingerprint.gpu_renderer = workerScope.webglRenderer;
    }
    if (typeof workerScope.timezoneLocation === "string") {
      fingerprint.timezone = workerScope.timezoneLocation;
    }
  }

  // GPU renderer fallback from canvasWebgl component
  if (!fingerprint.gpu_renderer) {
    const gpu = device.canvasWebgl?.gpu as Record<string, unknown> | undefined;
    if (gpu?.compressedGPU && typeof gpu.compressedGPU === "string") {
      fingerprint.gpu_renderer = gpu.compressedGPU;
    }
  }

  // Screen dimensions
  const screen = device.screen;
  if (screen) {
    const width = screen.width;
    const height = screen.height;
    if (typeof width === "number" && typeof height === "number") {
      fingerprint.screen_dims = `${width}x${height}`;
    }
  }

  // Component hashes
  if (hashes.canvas2d) {
    fingerprint.canvas_hash = hashes.canvas2d;
  }
  if (hashes.canvasWebgl) {
    fingerprint.webgl_hash = hashes.canvasWebgl;
  }
  if (hashes.offlineAudioContext) {
    fingerprint.audio_hash = hashes.offlineAudioContext;
  }
  if (hashes.maths) {
    fingerprint.maths_hash = hashes.maths;
  }

  // Sigint (network intelligence)
  if (sigint) {
    if (sigint.tlsFingerprint) {
      const tls = sigint.tlsFingerprint;
      if (tls.ip) fingerprint.ip_address = tls.ip;
      if (tls.ja3) fingerprint.ja3 = tls.ja3;
      if (tls.ja4) fingerprint.ja4 = tls.ja4;
      if (tls.id) fingerprint.sigint_id = tls.id;
    }
    if (sigint.tcpProbe) {
      const tcp = sigint.tcpProbe as Record<string, unknown>;
      const rttFp = tcp.rtt_fingerprint as Record<string, unknown> | undefined;
      if (rttFp) {
        if (typeof rttFp.proxy_score === "number") {
          fingerprint.proxy_score = rttFp.proxy_score;
        }
        if (typeof rttFp.vpn_score === "number") {
          fingerprint.vpn_score = rttFp.vpn_score;
        }
        if (typeof rttFp.tcp_rtt_us === "number") {
          fingerprint.tcp_rtt_us = rttFp.tcp_rtt_us;
        }
      } else {
        if (typeof tcp.proxyScore === "number") {
          fingerprint.proxy_score = tcp.proxyScore;
        }
        if (typeof tcp.vpnScore === "number") {
          fingerprint.vpn_score = tcp.vpnScore;
        }
        if (typeof tcp.rttMs === "number") {
          fingerprint.tcp_rtt_us = (tcp.rttMs as number) * 1000;
        }
      }
    }
    if (sigint.faviconCache?.id) {
      fingerprint.favicon_cache_id = sigint.faviconCache.id;
    }
    // STUN data - handle both field naming conventions
    const stun = sigint.stun as Record<string, unknown> | undefined;
    if (stun) {
      const publicIp = stun.publicIp ?? stun.reflexiveIp;
      if (typeof publicIp === "string") {
        fingerprint.stun_public_ip = publicIp;
      }
      const localIp =
        stun.localIp ?? (stun.localIps as string[] | undefined)?.[0];
      if (typeof localIp === "string") {
        fingerprint.stun_local_ip = localIp;
      }
    }
  }

  // Headless/bot detection signals
  const headless = device.headless as Record<string, unknown> | undefined;
  if (headless) {
    if (typeof headless.isHeadless === "boolean") {
      fingerprint.is_headless = headless.isHeadless;
    } else {
      const headlessSignals = headless.headless as
        | Record<string, boolean>
        | undefined;
      if (headlessSignals) {
        fingerprint.is_headless = Object.values(headlessSignals).some(Boolean);
      }
    }
  }

  const lies = device.lies as Record<string, unknown> | undefined;
  if (lies) {
    if (typeof lies.count === "number") {
      fingerprint.lie_count = lies.count;
    } else if (typeof lies.totalLies === "number") {
      fingerprint.lie_count = lies.totalLies;
    }
  }

  return fingerprint;
}
