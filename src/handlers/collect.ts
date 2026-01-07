// src/handlers/collect.ts
// Main fingerprint collection endpoint for Argus API
import { Logger } from '@aws-lambda-powertools/logger';
import { Metrics } from '@aws-lambda-powertools/metrics';

import middy from '@middy/core';
import httpHeaderNormalizer from '@middy/http-header-normalizer';
import httpErrorHandler from '@middy/http-error-handler';
import warmup from '@middy/warmup';
import httpJsonBodyParser from '@middy/http-json-body-parser';
import cors from '@middy/http-cors';
import validator from '@middy/validator';
import { transpileSchema } from '@middy/validator/transpile';

import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';
import { isWarmingUp, onWarmup, deduplicateMiddleware } from '../helpers/middy-helpers';
import createHttpError from 'http-errors';
import { POWERTOOLS_SERVICE_NAME } from '../helpers/constants';
import { flattenObject, getCurrentDateInfo, NestedValue } from '../helpers/misc';

// Powertools
const TOOL_NAME = `${POWERTOOLS_SERVICE_NAME}-collect`;
export const logger = new Logger({ serviceName: TOOL_NAME });
export const metrics = new Metrics({ namespace: POWERTOOLS_SERVICE_NAME || 'argus', serviceName: TOOL_NAME });

// SNS client (reused across invocations)
export const snsClient = new SNSClient({});

// Request validation schema
const collectSchema = {
  type: 'object',
  properties: {
    body: {
      type: 'object',
      required: ['session_id'],
      additionalProperties: true,
      properties: {
        session_id: {
          type: 'string',
          minLength: 1,
          maxLength: 128,
        },
        // JS fingerprint data
        js_fingerprint: {
          type: 'object',
          additionalProperties: true,
        },
        // Encrypted TCP fingerprint blob from tcp-probe
        tcp_blob: {
          type: 'string',
          maxLength: 10000,
        },
        // Encrypted TLS fingerprint blob from edge
        tls_blob: {
          type: 'string',
          maxLength: 5000,
        },
      },
    },
  },
  required: ['body'],
};

/**
 * Main handler for fingerprint collection
 * Receives JS fingerprint + encrypted TCP/TLS blobs
 * Publishes combined data to SNS for processing
 */
export const lambdaHandler = async (
  event: APIGatewayProxyEventV2,
): Promise<APIGatewayProxyResultV2> => {
  // Handle health check
  if (event.requestContext?.http?.method === 'GET' && event.rawPath === '/health') {
    return {
      statusCode: 200,
      body: JSON.stringify({ status: 'ok', service: 'ms-argus-api' }),
    };
  }

  try {
    const topicArn = process.env.FINGERPRINT_TOPIC_ARN;
    if (!topicArn) {
      throw new Error('FINGERPRINT_TOPIC_ARN is not set');
    }

    const { body, headers } = event;
    const ipAddress = event.requestContext?.http?.sourceIp;

    if (!ipAddress) throw new Error('No IP Address on identity');
    if (!headers) throw new Error('No headers given on request');
    if (!body) throw new Error('No body provided on event');

    // Extract request data
    // @ts-expect-error - body is parsed by httpJsonBodyParser
    const { session_id, js_fingerprint, tcp_blob, tls_blob } = body;

    // Build payload with date info
    const DATE_INFO: NestedValue = getCurrentDateInfo() as NestedValue;

    // Flatten JS fingerprint data
    const flatJsFingerprint = js_fingerprint
      ? flattenObject({ js: js_fingerprint })
      : {};

    // Combined payload
    const payload = {
      session_id,
      ipAddress,
      // Include encrypted blobs as-is (will be decrypted by analysis Lambda)
      tcp_blob: tcp_blob || null,
      tls_blob: tls_blob || null,
      // Flattened JS fingerprint
      ...flatJsFingerprint,
      // Request headers (useful for analysis)
      'headers.user_agent': headers['user-agent'],
      'headers.accept': headers['accept'],
      'headers.accept_language': headers['accept-language'],
      'headers.accept_encoding': headers['accept-encoding'],
      'headers.referer': headers['referer'],
      'headers.origin': headers['origin'],
      'headers.x_forwarded_for': headers['x-forwarded-for'],
      // Date partitioning info
      ...flattenObject({ DATE_INFO }),
      // Metadata
      'meta.timestamp': Date.now(),
      'meta.argus_version': '1.0.0',
    };

    // Publish to SNS
    await snsClient.send(
      new PublishCommand({
        TopicArn: topicArn,
        Message: JSON.stringify(payload) + '\n',
      }),
    );

    logger.info('Successfully processed fingerprint', { session_id, ipAddress });
    metrics.addMetric('FingerprintCollected', 'Count', 1);

    return {
      statusCode: 200,
      body: JSON.stringify({
        status: 'ok',
        session_id,
      }),
    };
  } catch (error) {
    logger.error('Error processing fingerprint', { error });
    metrics.addMetric('FingerprintError', 'Count', 1);
    throw createHttpError(500, 'Internal Server Error');
  }
};

// Middleware stack
export const handler = middy(lambdaHandler)
  .use(warmup({ isWarmingUp, onWarmup }))
  .use(deduplicateMiddleware())
  .use(httpHeaderNormalizer())
  .use(httpJsonBodyParser())
  .use(validator({ eventSchema: transpileSchema(collectSchema) }))
  .use(cors({ origin: '*', credentials: true }))
  .use(
    httpErrorHandler({
      fallbackMessage: 'An unexpected error occurred',
      logger: (error) => logger.error('HTTP error', { error }),
    }),
  );
