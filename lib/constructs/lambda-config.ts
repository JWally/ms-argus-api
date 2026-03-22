// lib/constructs/lambda-config.ts

// Provides consistent Lambda settings across all functions

import * as lambda from "aws-cdk-lib/aws-lambda";
import * as lambdaNode from "aws-cdk-lib/aws-lambda-nodejs";

/**
 * Base Lambda configuration options
 */
export interface BaseLambdaConfigOptions {
  /** Enable X-Ray tracing (default: false for API handlers, true for workers) */
  tracing?: boolean;
  /** Include keepNames in bundling for better stack traces (default: false) */
  keepNames?: boolean;
}

/**
 * Base bundling configuration shared by all Lambda functions.
 * Optimized for:
 * - Fast cold starts (ESM format, tree-shaking)
 * - Debugging in production (source maps)
 * - Minimal bundle size (minify)
 */
export const BASE_BUNDLING_CONFIG: lambdaNode.BundlingOptions = {
  minify: true,
  sourceMap: true,
  target: "node20",
  format: lambdaNode.OutputFormat.ESM,
  mainFields: ["module", "main"],
  // Polyfill require() for dependencies that use CJS dynamic requires of Node builtins
  banner:
    "import { createRequire } from 'module'; const require = createRequire(import.meta.url);",
  esbuildArgs: {
    "--tree-shaking": "true",
  },
};

/**
 * Creates base Lambda configuration to spread into NodejsFunction props.
 * Use for consistent runtime, architecture, and bundling across all functions.
 *
 * @param options - Optional configuration overrides
 * @returns Partial NodejsFunction props to spread
 *
 * @example
 * ```typescript
 * const fn = new NodejsFunction(this, "MyFunction", {
 *   ...createBaseLambdaConfig({ tracing: true }),
 *   entry: path.join(__dirname, "handler.ts"),
 *   functionName: "my-function",
 *   memorySize: 256,
 * });
 * ```
 */
export function createBaseLambdaConfig(
  options: BaseLambdaConfigOptions = {},
): Partial<lambdaNode.NodejsFunctionProps> {
  const { tracing = false, keepNames = false } = options;

  const bundling: lambdaNode.BundlingOptions = {
    ...BASE_BUNDLING_CONFIG,
    ...(keepNames && { keepNames: true }),
    // Remove esbuildArgs when using keepNames (they're incompatible)
    ...(keepNames && { esbuildArgs: undefined }),
  };

  return {
    runtime: lambda.Runtime.NODEJS_20_X,
    architecture: lambda.Architecture.ARM_64,
    bundling,
    ...(tracing && { tracing: lambda.Tracing.ACTIVE }),
  };
}

/**
 * Creates base environment variables for Powertools integration.
 *
 * @param serviceName - Service name for Powertools Logger
 * @param metricsNamespace - CloudWatch metrics namespace
 * @returns Environment variables object
 */
export function createPowertoolsEnv(
  serviceName: string,
  metricsNamespace: string,
): Record<string, string> {
  return {
    POWERTOOLS_SERVICE_NAME: serviceName,
    POWERTOOLS_METRICS_NAMESPACE: metricsNamespace,
    NODE_OPTIONS: "--enable-source-maps",
  };
}

/**
 * Creates environment variables for worker Lambdas with connection reuse.
 *
 * @param stage - Deployment stage
 * @param stackName - Stack name for metrics namespace
 * @param serviceName - Service name for Powertools Logger
 * @returns Environment variables object
 */
export function createWorkerEnv(
  stage: string,
  stackName: string,
  serviceName: string,
): Record<string, string> {
  return {
    AWS_NODEJS_CONNECTION_REUSE_ENABLED: "1",
    ENVIRONMENT: stage,
    POWERTOOLS_SERVICE_NAME: serviceName,
    POWERTOOLS_METRICS_NAMESPACE: stackName,
    LOG_LEVEL: "INFO",
  };
}

/**
 * Creates Lambda configuration for functions that use the Qdrant client.
 * Uses CommonJS format to avoid ESM compatibility issues with the Qdrant client.
 *
 * @param options - Optional configuration overrides
 * @returns Partial NodejsFunction props to spread
 */
export function createVectorLambdaConfig(
  options: BaseLambdaConfigOptions = {},
): Partial<lambdaNode.NodejsFunctionProps> {
  const { tracing = true, keepNames = true } = options;

  const bundling: lambdaNode.BundlingOptions = {
    minify: true,
    sourceMap: true,
    target: "node20",
    // Use CJS format for Qdrant client compatibility
    format: lambdaNode.OutputFormat.CJS,
    mainFields: ["main", "module"],
    ...(keepNames && { keepNames: true }),
  };

  return {
    runtime: lambda.Runtime.NODEJS_20_X,
    architecture: lambda.Architecture.ARM_64,
    bundling,
    ...(tracing && { tracing: lambda.Tracing.ACTIVE }),
  };
}
