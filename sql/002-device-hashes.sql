-- 002-device-hashes.sql
-- Consolidate T1 (stable hash) + T1.5 (SimHash) into a single device_hashes table.
-- One row per device, one query covers both tiers.

BEGIN;

-- =========================================================================
-- device_hashes: Unified T1 + T1.5 table
-- Replaces separate tier1_index (hash lookups) and simhash_devices tables
-- =========================================================================

CREATE TABLE IF NOT EXISTS device_hashes (
  device_id    TEXT PRIMARY KEY,
  stable_hash  TEXT,                     -- stable hash for exact T1 match
  fuzzy_hash   BIT(256),                 -- full 256-bit SimHash for bit_count(XOR)
  band_0       BIT(16), band_1  BIT(16), band_2  BIT(16), band_3  BIT(16),
  band_4       BIT(16), band_5  BIT(16), band_6  BIT(16), band_7  BIT(16),
  band_8       BIT(16), band_9  BIT(16), band_10 BIT(16), band_11 BIT(16),
  band_12      BIT(16), band_13 BIT(16), band_14 BIT(16), band_15 BIT(16),
  last_seen    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at   TIMESTAMPTZ NOT NULL
);

-- T1: Exact stable hash lookup
CREATE INDEX IF NOT EXISTS idx_device_stable ON device_hashes (stable_hash) WHERE stable_hash IS NOT NULL;

-- T1.5: LSH band indexes for SimHash pre-filtering
CREATE INDEX IF NOT EXISTS idx_dh_band_0  ON device_hashes (band_0);
CREATE INDEX IF NOT EXISTS idx_dh_band_1  ON device_hashes (band_1);
CREATE INDEX IF NOT EXISTS idx_dh_band_2  ON device_hashes (band_2);
CREATE INDEX IF NOT EXISTS idx_dh_band_3  ON device_hashes (band_3);
CREATE INDEX IF NOT EXISTS idx_dh_band_4  ON device_hashes (band_4);
CREATE INDEX IF NOT EXISTS idx_dh_band_5  ON device_hashes (band_5);
CREATE INDEX IF NOT EXISTS idx_dh_band_6  ON device_hashes (band_6);
CREATE INDEX IF NOT EXISTS idx_dh_band_7  ON device_hashes (band_7);
CREATE INDEX IF NOT EXISTS idx_dh_band_8  ON device_hashes (band_8);
CREATE INDEX IF NOT EXISTS idx_dh_band_9  ON device_hashes (band_9);
CREATE INDEX IF NOT EXISTS idx_dh_band_10 ON device_hashes (band_10);
CREATE INDEX IF NOT EXISTS idx_dh_band_11 ON device_hashes (band_11);
CREATE INDEX IF NOT EXISTS idx_dh_band_12 ON device_hashes (band_12);
CREATE INDEX IF NOT EXISTS idx_dh_band_13 ON device_hashes (band_13);
CREATE INDEX IF NOT EXISTS idx_dh_band_14 ON device_hashes (band_14);
CREATE INDEX IF NOT EXISTS idx_dh_band_15 ON device_hashes (band_15);

-- Expiration cleanup index
CREATE INDEX IF NOT EXISTS idx_device_hashes_expires ON device_hashes (expires_at);

-- Drop old tables (all data is disposable in dev)
DROP TABLE IF EXISTS tier1_index;
DROP TABLE IF EXISTS simhash_devices;

COMMIT;
