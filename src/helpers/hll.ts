/**
 * Minimal HyperLogLog implementation for distinct-count estimation.
 *
 * Used by ip-velocity to estimate distinct devices per (ip, hour-bucket).
 * Pure TypeScript, no external dependency — the serialized format is
 * stable and owned by this module (small Buffer with a 1-byte version
 * prefix), so future migration to Redis-native HLL would just re-walk
 * recent traffic instead of bit-copying state.
 *
 * Algorithm: standard HLL with 2^p registers. We use p=12 → 4096
 * registers, each 6 bits packed densely. Serialized size: 1 byte
 * (version) + 1 byte (p) + ceil(4096*6/8) = ~3074 bytes total.
 * Standard error at p=12: 1.04/sqrt(4096) ≈ 1.6% (relative).
 *
 * At low cardinalities (< 5 * m), HLL switches to "linear counting"
 * internally — for the residential-device-count case (2-8 distinct on
 * a household IP) this is effectively exact. The 1.6% error only kicks
 * in past ~thousands of distinct entries, where exactness stops
 * mattering for fraud decisions anyway.
 */

import { createHash } from "node:crypto";

const VERSION = 1;
const HLL_P = 12;
const HLL_M = 1 << HLL_P; // 4096
const REGISTER_BITS = 6;

/** Header bytes before the packed register array. */
const HEADER_BYTES = 2;
const REGISTER_BYTES = Math.ceil((HLL_M * REGISTER_BITS) / 8);
export const HLL_SERIALIZED_BYTES = HEADER_BYTES + REGISTER_BYTES;

export class Hll {
  /** Raw register values, 0..63. Length = HLL_M. */
  private readonly registers: Uint8Array;

  constructor(registers?: Uint8Array) {
    if (registers) {
      if (registers.length !== HLL_M) {
        throw new Error(`Hll register count mismatch: ${registers.length}`);
      }
      this.registers = registers;
    } else {
      this.registers = new Uint8Array(HLL_M);
    }
  }

  /** Add one element. `input` should already be a stable identifier
   *  (e.g. a hash of the device pubkey). We hash again here so the HLL
   *  registers see a uniformly distributed 64-bit value. */
  add(input: string | Buffer): void {
    const buf = typeof input === "string" ? Buffer.from(input, "utf-8") : input;
    const h = createHash("sha256").update(buf).digest();
    // Bucket index from the top HLL_P bits of the hash.
    const idx = (h.readUInt32BE(0) >>> (32 - HLL_P)) & ((1 << HLL_P) - 1);
    // Remaining bits: count leading zeros + 1. Use the next 32 bits;
    // the HLL_P bits already consumed are masked out by left-shift.
    const remaining = (h.readUInt32BE(0) << HLL_P) >>> 0;
    // Combine with the second 32 bits for tail bits beyond 32-HLL_P.
    const tailHi = h.readUInt32BE(4);
    let lz = leadingZeros32(remaining);
    if (lz === 32 - HLL_P) {
      // All bits in the shifted word were zero — keep counting in the
      // next 32-bit word.
      lz = 32 - HLL_P + leadingZeros32(tailHi);
    }
    const rank = lz + 1;
    if (rank > this.registers[idx]) {
      this.registers[idx] = rank;
    }
  }

  /** Merge another HLL into this one (register-wise max). Same size
   *  required. */
  merge(other: Hll): void {
    for (let i = 0; i < HLL_M; i++) {
      if (other.registers[i] > this.registers[i]) {
        this.registers[i] = other.registers[i];
      }
    }
  }

  /** Estimated number of distinct items added. Uses the standard HLL
   *  bias-corrected estimator with linear counting at low cardinalities. */
  count(): number {
    let zeros = 0;
    let sum = 0;
    for (let i = 0; i < HLL_M; i++) {
      const r = this.registers[i];
      if (r === 0) zeros++;
      sum += 1 / Math.pow(2, r);
    }
    // Linear counting when many registers are still zero — much more
    // accurate at small cardinalities.
    if (zeros !== 0) {
      const linear = HLL_M * Math.log(HLL_M / zeros);
      if (linear < (5 * HLL_M) / 2) return Math.round(linear);
    }
    // Standard HLL estimator. alpha for m=4096 ≈ 0.7213 / (1 + 1.079/m)
    const alpha = 0.7213 / (1 + 1.079 / HLL_M);
    const raw = (alpha * HLL_M * HLL_M) / sum;
    return Math.round(raw);
  }

  /** Serialize to bytes for DDB storage. Layout:
   *  [0] version (1 byte), [1] p (1 byte), [2..] packed registers. */
  toBytes(): Buffer {
    const out = Buffer.alloc(HLL_SERIALIZED_BYTES);
    out[0] = VERSION;
    out[1] = HLL_P;
    packRegisters(this.registers, out, HEADER_BYTES);
    return out;
  }

  /** Reconstruct from bytes. Throws on version or size mismatch. */
  static fromBytes(bytes: Buffer | Uint8Array): Hll {
    if (bytes.length !== HLL_SERIALIZED_BYTES) {
      throw new Error(
        `Hll byte length mismatch: ${bytes.length} expected ${HLL_SERIALIZED_BYTES}`,
      );
    }
    const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
    if (buf[0] !== VERSION) {
      throw new Error(`Hll version mismatch: ${buf[0]} expected ${VERSION}`);
    }
    if (buf[1] !== HLL_P) {
      throw new Error(`Hll p mismatch: ${buf[1]} expected ${HLL_P}`);
    }
    const registers = unpackRegisters(buf, HEADER_BYTES);
    return new Hll(registers);
  }

  static empty(): Hll {
    return new Hll();
  }
}

function leadingZeros32(n: number): number {
  if (n === 0) return 32;
  let count = 0;
  let v = n >>> 0;
  while ((v & 0x80000000) === 0) {
    count++;
    v = (v << 1) >>> 0;
  }
  return count;
}

/** Pack m registers of REGISTER_BITS bits each into `out` starting at
 *  byte offset `off`. Little-endian within each byte. */
function packRegisters(registers: Uint8Array, out: Buffer, off: number): void {
  let bitPos = 0;
  for (let i = 0; i < HLL_M; i++) {
    const value = registers[i] & ((1 << REGISTER_BITS) - 1);
    const byteIdx = off + (bitPos >>> 3);
    const bitOff = bitPos & 7;
    // Up to two bytes touched per register at REGISTER_BITS=6.
    out[byteIdx] |= (value << bitOff) & 0xff;
    if (bitOff + REGISTER_BITS > 8) {
      out[byteIdx + 1] |= value >> (8 - bitOff);
    }
    bitPos += REGISTER_BITS;
  }
}

function unpackRegisters(buf: Buffer, off: number): Uint8Array {
  const registers = new Uint8Array(HLL_M);
  let bitPos = 0;
  const mask = (1 << REGISTER_BITS) - 1;
  for (let i = 0; i < HLL_M; i++) {
    const byteIdx = off + (bitPos >>> 3);
    const bitOff = bitPos & 7;
    let value = (buf[byteIdx] >> bitOff) & mask;
    if (bitOff + REGISTER_BITS > 8) {
      value |= (buf[byteIdx + 1] << (8 - bitOff)) & mask;
    }
    registers[i] = value;
    bitPos += REGISTER_BITS;
  }
  return registers;
}
