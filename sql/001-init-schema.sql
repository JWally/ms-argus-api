-- 001-init-schema.sql
-- PostgreSQL schema for Argus T1/T1.5 fingerprint matching
-- Replaces DynamoDB tier1IndexTable and tier2BucketsTable for SimHash matching

BEGIN;

-- =========================================================================
-- tier1_index: Point lookups by hash_key (replaces DynamoDB tier1IndexTable)
-- =========================================================================

CREATE TABLE IF NOT EXISTS tier1_index (
  hash_key    TEXT PRIMARY KEY,       -- "stable#<hash>" or "fuzzy#<hash>"
  device_id   TEXT NOT NULL,
  fuzzy_hash  TEXT,                   -- for drift detection
  expires_at  TIMESTAMPTZ NOT NULL    -- replaces DynamoDB TTL
);

CREATE INDEX IF NOT EXISTS idx_tier1_expires ON tier1_index (expires_at);

-- =========================================================================
-- simhash_devices: Denormalized SimHash table (replaces DynamoDB tier2BucketsTable)
-- One row per device with band columns for index-backed pre-filtering,
-- plus the full hash for inline Hamming scoring via bit_count(XOR).
-- =========================================================================

CREATE TABLE IF NOT EXISTS simhash_devices (
  device_id   TEXT PRIMARY KEY,
  fuzzy_hash  BIT(256) NOT NULL,      -- full 256-bit SimHash for bit_count(XOR)
  band_0      BIT(16) NOT NULL,       -- bands 0-15 extracted from fuzzy_hash
  band_1      BIT(16) NOT NULL,
  band_2      BIT(16) NOT NULL,
  band_3      BIT(16) NOT NULL,
  band_4      BIT(16) NOT NULL,
  band_5      BIT(16) NOT NULL,
  band_6      BIT(16) NOT NULL,
  band_7      BIT(16) NOT NULL,
  band_8      BIT(16) NOT NULL,
  band_9      BIT(16) NOT NULL,
  band_10     BIT(16) NOT NULL,
  band_11     BIT(16) NOT NULL,
  band_12     BIT(16) NOT NULL,
  band_13     BIT(16) NOT NULL,
  band_14     BIT(16) NOT NULL,
  band_15     BIT(16) NOT NULL,
  last_seen   TIMESTAMPTZ NOT NULL,
  expires_at  TIMESTAMPTZ NOT NULL
);

-- One index per band for LSH pre-filtering
-- (expired rows filtered at query time via WHERE expires_at > NOW())
CREATE INDEX IF NOT EXISTS idx_band_0  ON simhash_devices (band_0);
CREATE INDEX IF NOT EXISTS idx_band_1  ON simhash_devices (band_1);
CREATE INDEX IF NOT EXISTS idx_band_2  ON simhash_devices (band_2);
CREATE INDEX IF NOT EXISTS idx_band_3  ON simhash_devices (band_3);
CREATE INDEX IF NOT EXISTS idx_band_4  ON simhash_devices (band_4);
CREATE INDEX IF NOT EXISTS idx_band_5  ON simhash_devices (band_5);
CREATE INDEX IF NOT EXISTS idx_band_6  ON simhash_devices (band_6);
CREATE INDEX IF NOT EXISTS idx_band_7  ON simhash_devices (band_7);
CREATE INDEX IF NOT EXISTS idx_band_8  ON simhash_devices (band_8);
CREATE INDEX IF NOT EXISTS idx_band_9  ON simhash_devices (band_9);
CREATE INDEX IF NOT EXISTS idx_band_10 ON simhash_devices (band_10);
CREATE INDEX IF NOT EXISTS idx_band_11 ON simhash_devices (band_11);
CREATE INDEX IF NOT EXISTS idx_band_12 ON simhash_devices (band_12);
CREATE INDEX IF NOT EXISTS idx_band_13 ON simhash_devices (band_13);
CREATE INDEX IF NOT EXISTS idx_band_14 ON simhash_devices (band_14);
CREATE INDEX IF NOT EXISTS idx_band_15 ON simhash_devices (band_15);

-- Expiration cleanup index
CREATE INDEX IF NOT EXISTS idx_simhash_expires ON simhash_devices (expires_at);

COMMIT;
