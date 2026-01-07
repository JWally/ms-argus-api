// bin/config.ts
// Configuration for ms-argus-api deployment
// Update these values for your environment

export const PIPELINE_NAME: string = 'ms-argus-api';
export const ROOT_DOMAIN: string = 'signifyd.com'; // Update to your domain
export const SITE_DOMAIN: string = 'signifyd.com';

// AWS Account and Region - update these for your environment
export const AWS_ACCOUNT_ID: string = process.env.CDK_DEFAULT_ACCOUNT || '123456789012';
export const PIPELINE_HOME_REGION: string = process.env.CDK_DEFAULT_REGION || 'us-east-1';
