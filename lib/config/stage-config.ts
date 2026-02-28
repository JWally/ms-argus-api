// lib/config/stage-config.ts

// This provides a single source of truth for environment-specific values
//
// Lambda Power Tuning Notes:
// To optimize Lambda memory settings, use AWS Lambda Power Tuning:
// https://github.com/alexcasalboni/aws-lambda-power-tuning
//
// Deploy via SAR:
// aws serverlessrepo create-cloud-formation-template \
//   --application-id arn:aws:serverlessrepo:us-east-1:451282441545:applications/aws-lambda-power-tuning
//
// Memory settings below are initial estimates. Run Power Tuning against
// real workloads to find optimal cost/performance balance for each function.

import { Duration } from "aws-cdk-lib";

/**
 * Stage-specific configuration for infrastructure resources
 * All tunable values that should vary between dev and prod belong here
 */
export interface StageConfig {
  // Lambda configuration

  lambda: {
    matching: {
      memorySize: number; // SQS consumer - tier matching (CPU-bound with hashing)
      timeout: Duration;
      reservedConcurrency: number;
    };
    profile: {
      memorySize: number; // SQS consumer - profile updates (I/O-bound)
      timeout: Duration;
      reservedConcurrency: number;
    };
    ingestion: {
      memorySize: number; // API handler - fingerprint ingestion (I/O-bound, minimal CPU)
    };
    sessionGet: {
      memorySize: number; // API handler - session retrieval (simple read, minimal CPU)
    };
    vectorWorker: {
      memorySize: number; // VPC Lambda - QDrant vector operations
      timeout: Duration;
      reservedConcurrency: number;
    };
    provisionedConcurrency: number;
    /** Enable X-Ray tracing for worker Lambdas (expensive in dev with no traffic) */
    tracingEnabled: boolean;
  };

  // SQS configuration
  sqs: {
    visibilityTimeout: Duration;
    retentionPeriod: Duration;
    maxReceiveCount: number;
    batchingWindow: {
      matching: Duration;
      profile: Duration;
    };
  };

  // These were kept for historical reference but are no longer used

  // CloudWatch alarm thresholds
  alarms: {
    enabled: boolean;
    lambda: {
      errorThreshold: number;
      throttleThreshold: number;
      durationThresholdMs: number;
      concurrencyPercent: number;
    };
    queue: {
      backlogThreshold: number;
      messageAgeSeconds: number;
    };

    dynamodb: {
      throttleThreshold: number;
      errorThreshold: number;
    };

    newDeviceAnomalyStdDev: number;
  };

  // WAF configuration
  waf: {
    enabled: boolean;
    rateLimitPerFiveMinutes: number;
    bodySizeLimitBytes: number;
  };

  dynamodb: {
    // If true, use provisioned capacity with auto-scaling; if false, use PAY_PER_REQUEST
    useProvisionedCapacity: boolean;
    // Base read/write capacity units (only used if useProvisionedCapacity is true)
    baseReadCapacity: number;
    baseWriteCapacity: number;
    // Auto-scaling configuration
    autoScaling: {
      targetUtilizationPercent: number; // Target utilization (e.g., 70%)
      maxCapacityMultiplier: number; // Max capacity as multiplier of base (e.g., 2 = 200%)
    };
  };

  // Valkey (ElastiCache Serverless) configuration for statistical anomaly detection
  valkey: {
    // Whether Valkey is enabled for this stage
    enabled: boolean;
    // Maximum data storage in GiB (ElastiCache Serverless billing unit)
    maxDataStorageGiB: number;
    // TTL for statistical keys in seconds (default 48h = 172800)
    ttlSeconds: number;
    // Score threshold below which combo is considered suspicious (0.01 = 1%)
    scoreThreshold: number;
    // Minimum distinct combos required before statistical detection activates
    distinctThreshold: number;
    // Global sampling rate for write-side counters (0.01 = 1%, 1.0 = 100%)
    // Low values reduce Valkey write load; high values give faster convergence
    globalSampleRate: number;
    // Statistical v2: Shannon scoring with dual-layer fingerprints (JA4 + H2)
    statisticalV2: {
      // Whether statistical v2 detection is enabled
      enabled: boolean;
      // Score threshold for flagging anomalies (0.6 = 60% surprise)
      threshold: number;
      // Sample thresholds for tiered TTLs [low, high]
      tierThresholds: [number, number];
      // TTLs in seconds for [cold, warm, hot] tiers
      tierTTLs: [number, number, number];
    };
  };
}

/**
 * Development environment configuration
 * Optimized for: low cost, fast feedback, adequate for testing
 */
const devConfig: StageConfig = {
  lambda: {
    matching: {
      // Production should use power tuning results; dev optimizes for cold start speed
      memorySize: 1024,
      timeout: Duration.seconds(20),
      reservedConcurrency: 25,
    },
    profile: {
      memorySize: 128,
      timeout: Duration.seconds(15),
      reservedConcurrency: 25,
    },
    ingestion: {
      memorySize: 256, // Minimal processing - just validation and SQS publish
    },
    sessionGet: {
      memorySize: 256, // Simple DynamoDB read
    },
    vectorWorker: {
      memorySize: 512, // Network I/O to QDrant
      timeout: Duration.seconds(30),
      reservedConcurrency: 10, // Low concurrency in dev
    },
    provisionedConcurrency: 0, // No warm instances in dev
    tracingEnabled: false, // X-Ray costs ~$5/month with no benefit in dev
  },

  sqs: {
    visibilityTimeout: Duration.seconds(30),
    retentionPeriod: Duration.days(1),
    maxReceiveCount: 1, // Fail fast in dev for debugging
    batchingWindow: {
      matching: Duration.seconds(0),
      profile: Duration.seconds(0),
    },
  },

  alarms: {
    enabled: false,
    lambda: {
      errorThreshold: 5,
      throttleThreshold: 1,
      durationThresholdMs: 20000,
      concurrencyPercent: 70,
    },
    queue: {
      backlogThreshold: 1000,
      messageAgeSeconds: 60,
    },
    dynamodb: {
      throttleThreshold: 2,
      errorThreshold: 1,
    },

    newDeviceAnomalyStdDev: 2,
  },

  waf: {
    enabled: false,
    rateLimitPerFiveMinutes: 100000,
    bodySizeLimitBytes: 102400, // 100KB
  },

  // DynamoDB billing - use PAY_PER_REQUEST for dev to avoid throughput limits during testing

  dynamodb: {
    useProvisionedCapacity: false, // On-demand for dev - no throughput limits
    baseReadCapacity: 0,
    baseWriteCapacity: 0,
    autoScaling: {
      targetUtilizationPercent: 70,
      maxCapacityMultiplier: 2,
    },
  },

  // Valkey - enabled in dev for statistical anomaly detection testing
  valkey: {
    enabled: true,
    maxDataStorageGiB: 1, // Minimal storage for dev (~$6/mo)
    ttlSeconds: 172800, // 48 hours
    scoreThreshold: 0.01, // 1% - combo appears less than 1% of expected = suspicious
    distinctThreshold: 50, // Need at least 50 distinct combos before detection activates
    globalSampleRate: 1.0, // 100% in dev - every request updates global counters
    // Statistical v2: enabled for dev testing
    statisticalV2: {
      enabled: true,
      threshold: 0.6, // 60% surprise triggers anomaly
      tierThresholds: [1000, 20000], // [warm threshold, hot threshold]
      tierTTLs: [3 * 3600, 24 * 3600, 90 * 24 * 3600], // [3h, 24h, 90d]
    },
  },
};

/**
 * Production environment configuration
 * Optimized for: performance, reliability, appropriate headroom
 */
const prodConfig: StageConfig = {
  lambda: {
    matching: {
      // Current setting is cost-optimized; may need increase for latency SLAs
      memorySize: 512,
      timeout: Duration.seconds(45),
      reservedConcurrency: 1000,
    },
    profile: {
      memorySize: 256,
      timeout: Duration.seconds(30),
      reservedConcurrency: 500,
    },
    ingestion: {
      memorySize: 256, // Minimal processing - just validation and SQS publish
    },
    sessionGet: {
      memorySize: 256, // Simple DynamoDB read
    },
    vectorWorker: {
      memorySize: 512, // Network I/O to QDrant
      timeout: Duration.seconds(30),
      reservedConcurrency: 100, // Higher concurrency in prod
    },
    provisionedConcurrency: 2, // Keep 2 warm in prod
    tracingEnabled: true,
  },

  sqs: {
    visibilityTimeout: Duration.seconds(60),
    retentionPeriod: Duration.days(7),
    maxReceiveCount: 3,
    batchingWindow: {
      matching: Duration.seconds(0),
      profile: Duration.seconds(0),
    },
  },

  alarms: {
    enabled: true,
    lambda: {
      errorThreshold: 10,
      throttleThreshold: 5,
      durationThresholdMs: 30000,
      concurrencyPercent: 80,
    },
    queue: {
      backlogThreshold: 10000,
      messageAgeSeconds: 300,
    },
    dynamodb: {
      throttleThreshold: 10,
      errorThreshold: 5,
    },

    newDeviceAnomalyStdDev: 2,
  },

  waf: {
    enabled: true, // WAF enabled in production for security
    rateLimitPerFiveMinutes: 600,
    bodySizeLimitBytes: 102400, // 100KB
  },

  // Per FINAL-PLAN.md: Switch to provisioned 4 weeks before go-live after capacity analysis
  // Process: Set base capacity at 150% of p99, auto-scale to 200%
  // Expected savings: ~$31K/year once implemented
  dynamodb: {
    useProvisionedCapacity: false, // Stay on-demand until capacity analysis complete
    baseReadCapacity: 0, // Placeholder - set to 150% of p99 after analysis
    baseWriteCapacity: 0, // Placeholder - set to 150% of p99 after analysis
    autoScaling: {
      targetUtilizationPercent: 70,
      maxCapacityMultiplier: 2,
    },
  },

  // Valkey - enabled in prod for statistical anomaly detection
  valkey: {
    enabled: true,
    maxDataStorageGiB: 5, // Higher capacity for prod (~$12/mo)
    ttlSeconds: 172800, // 48 hours
    scoreThreshold: 0.01, // 1% - combo appears less than 1% of expected = suspicious
    distinctThreshold: 50, // Need at least 50 distinct combos before detection activates
    globalSampleRate: 0.01, // 1% in prod - sample to reduce write load
    // Statistical v2: disabled in prod (shadow mode)
    statisticalV2: {
      enabled: false, // Enable after validating in dev
      threshold: 0.6, // 60% surprise triggers anomaly
      tierThresholds: [1000, 20000], // [warm threshold, hot threshold]
      tierTTLs: [3 * 3600, 24 * 3600, 90 * 24 * 3600], // [3h, 24h, 90d]
    },
  },
};

/**
 * Stage configuration lookup table
 */
const STAGE_CONFIGS: Record<string, StageConfig> = {
  dev: devConfig,
  "dev-jw": devConfig,
  staging: devConfig, // Staging uses dev config (can be customized later)
  prod: prodConfig,
  production: prodConfig,
};

/**
 * Get configuration for a specific stage
 * Returns dev config for any unrecognized stage (safe default)
 *
 * @param stage - The deployment stage (e.g., 'dev', 'prod', 'dev-jw')
 * @returns Stage-specific configuration
 */
export function getStageConfig(stage: string): StageConfig {
  // Normalize stage name (handle suffixes like 'dev-jw')
  const normalizedStage = stage.startsWith("dev") ? "dev" : stage;
  return STAGE_CONFIGS[normalizedStage] || devConfig;
}

/**
 * Check if a stage is production
 * Useful for conditional logic that should only run in prod
 */
export function isProdStage(stage: string): boolean {
  return stage === "prod" || stage === "production";
}

/**
 * Export individual configs for testing
 */
export const configs = {
  dev: devConfig,
  prod: prodConfig,
};
