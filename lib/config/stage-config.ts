// lib/config/stage-config.ts
// AR-43: Centralized stage-specific configuration
// This provides a single source of truth for environment-specific values

import { Duration } from "aws-cdk-lib";

/**
 * Stage-specific configuration for infrastructure resources
 * All tunable values that should vary between dev and prod belong here
 */
export interface StageConfig {
  // Lambda configuration
  lambda: {
    matching: {
      memorySize: number;
      timeout: Duration;
      reservedConcurrency: number;
    };
    profile: {
      memorySize: number;
      timeout: Duration;
      reservedConcurrency: number;
    };
    provisionedConcurrency: number;
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

  // ECS configuration
  ecs: {
    cpu: number;
    memoryMiB: number;
    desiredCount: number;
    minCapacity: number;
    maxCapacity: number;
    cpuScalingThreshold: number;
    requestsPerTarget: number;
  };

  // Redis configuration
  redis: {
    nodeType: string;
    numNodes: number;
    multiAz: boolean;
    snapshotRetentionDays: number;
  };

  // CloudWatch alarm thresholds
  alarms: {
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
    redis: {
      memoryWarningPercent: number;
      memoryCriticalPercent: number;
      cpuThreshold: number;
      evictionsThreshold: number;
    };
    dynamodb: {
      throttleThreshold: number;
      errorThreshold: number;
    };
    // AR-123: New device rate anomaly detection
    newDeviceAnomalyStdDev: number;
    ecs: {
      cpuThreshold: number;
      latencyThresholdMs: number;
      errorThreshold: number;
    };
  };

  // WAF configuration
  waf: {
    enabled: boolean; // AR-51: WAF disabled in non-prod to reduce costs
    rateLimitPerFiveMinutes: number;
    bodySizeLimitBytes: number;
  };

  // AR-133: DynamoDB billing configuration
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
}

/**
 * Development environment configuration
 * Optimized for: low cost, fast feedback, adequate for testing
 */
const devConfig: StageConfig = {
  lambda: {
    matching: {
      memorySize: 1024,
      timeout: Duration.seconds(20),
      reservedConcurrency: 25,
    },
    profile: {
      memorySize: 128,
      timeout: Duration.seconds(15),
      reservedConcurrency: 25,
    },
    provisionedConcurrency: 0, // No warm instances in dev
  },

  sqs: {
    visibilityTimeout: Duration.seconds(30),
    retentionPeriod: Duration.days(1),
    maxReceiveCount: 1, // Fail fast in dev for debugging
    batchingWindow: {
      // AR-71: Set to 0 to minimize latency - don't wait for batching
      matching: Duration.seconds(0),
      profile: Duration.seconds(0),
    },
  },

  ecs: {
    cpu: 256,
    memoryMiB: 512, // Fargate minimum for 256 CPU
    desiredCount: 1,
    minCapacity: 1,
    maxCapacity: 2,
    cpuScalingThreshold: 80,
    requestsPerTarget: 10000,
  },

  redis: {
    nodeType: "cache.t4g.small",
    numNodes: 1,
    multiAz: false,
    snapshotRetentionDays: 1,
  },

  alarms: {
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
    redis: {
      memoryWarningPercent: 70,
      memoryCriticalPercent: 80,
      cpuThreshold: 60,
      evictionsThreshold: 10,
    },
    dynamodb: {
      throttleThreshold: 2,
      errorThreshold: 1,
    },
    // AR-123: Anomaly detection for new device rate (fraud indicator)
    newDeviceAnomalyStdDev: 2,
    ecs: {
      cpuThreshold: 75,
      latencyThresholdMs: 50,
      errorThreshold: 5,
    },
  },

  waf: {
    enabled: false, // AR-51: WAF disabled in dev to reduce costs (~$30/month savings)
    rateLimitPerFiveMinutes: 2000, // Higher limit in dev for testing
    bodySizeLimitBytes: 102400, // 100KB
  },

  // AR-133: DynamoDB provisioned capacity for dev - conservative values to test infrastructure
  dynamodb: {
    useProvisionedCapacity: true, // Test provisioned capacity in dev
    baseReadCapacity: 5, // Conservative base - enough for dev testing
    baseWriteCapacity: 5, // Conservative base - enough for dev testing
    autoScaling: {
      targetUtilizationPercent: 70, // Scale when 70% utilized
      maxCapacityMultiplier: 2, // Scale up to 200% of base (10 RCU/WCU)
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
      memorySize: 512,
      timeout: Duration.seconds(45),
      reservedConcurrency: 1000,
    },
    profile: {
      memorySize: 256,
      timeout: Duration.seconds(30),
      reservedConcurrency: 500,
    },
    provisionedConcurrency: 2, // Keep 2 warm in prod
  },

  sqs: {
    visibilityTimeout: Duration.seconds(60),
    retentionPeriod: Duration.days(7),
    maxReceiveCount: 3,
    batchingWindow: {
      // AR-71: Set to 0 to minimize latency - don't wait for batching
      matching: Duration.seconds(0),
      profile: Duration.seconds(0),
    },
  },

  ecs: {
    cpu: 256,
    memoryMiB: 512,
    desiredCount: 2,
    minCapacity: 2,
    maxCapacity: 10,
    cpuScalingThreshold: 70,
    requestsPerTarget: 5000,
  },

  redis: {
    nodeType: "cache.r6g.medium",
    numNodes: 2,
    multiAz: true,
    snapshotRetentionDays: 7,
  },

  alarms: {
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
    redis: {
      memoryWarningPercent: 70,
      memoryCriticalPercent: 80,
      cpuThreshold: 80,
      evictionsThreshold: 100,
    },
    dynamodb: {
      throttleThreshold: 10,
      errorThreshold: 5,
    },
    // AR-123: Anomaly detection for new device rate (fraud indicator)
    newDeviceAnomalyStdDev: 2,
    ecs: {
      cpuThreshold: 85,
      latencyThresholdMs: 10,
      errorThreshold: 10,
    },
  },

  waf: {
    enabled: true, // WAF enabled in production for security
    rateLimitPerFiveMinutes: 600,
    bodySizeLimitBytes: 102400, // 100KB
  },

  // AR-133: DynamoDB - keep PAY_PER_REQUEST in prod until capacity analysis is done
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
