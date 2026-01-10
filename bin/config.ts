// bin/config.ts
// Configuration for ms-argus-api deployment

export const PIPELINE_NAME: string = 'ms-argus-api';
export const ROOT_DOMAIN: string = 'argus.pw';
export const SITE_DOMAIN: string = 'argus.pw';

// AWS Account and Region
export const AWS_ACCOUNT_ID: string = process.env.CDK_DEFAULT_ACCOUNT || '';
export const PIPELINE_HOME_REGION: string = 'us-east-1';
