#!/usr/bin/env node
// bin/ms-argus-api.ts
import { App, CliCredentialsStackSynthesizer } from 'aws-cdk-lib';
import { ArgusApiStack } from '../lib/stacks/app-stack';
import { ROOT_DOMAIN, AWS_ACCOUNT_ID, PIPELINE_HOME_REGION } from './config';

const app = new App();

// Use CLI credentials directly to avoid bootstrap role issues
const synthesizer = new CliCredentialsStackSynthesizer();

// /////////////////////////////////
// Development stack (jw)
// Run: cdk deploy ms-argus-api-dev-jw
// /////////////////////////////////
new ArgusApiStack(app, 'ms-argus-api-dev-jw', {
  env: { account: AWS_ACCOUNT_ID, region: PIPELINE_HOME_REGION },
  environment: 'dev-jw',
  stackName: 'ms-argus-api-dev-jw',
  rootDomain: ROOT_DOMAIN,
  stage: 'dev',
  region: PIPELINE_HOME_REGION,
  account: AWS_ACCOUNT_ID,
  synthesizer,
});

// /////////////////////////////////
// Production stack (when ready)
// Run: cdk deploy ms-argus-api-prod
// /////////////////////////////////
// new ArgusApiStack(app, 'ms-argus-api-prod', {
//   env: { account: AWS_ACCOUNT_ID, region: PIPELINE_HOME_REGION },
//   environment: 'prod',
//   stackName: 'ms-argus-api-prod',
//   rootDomain: ROOT_DOMAIN,
//   stage: 'prod',
//   region: PIPELINE_HOME_REGION,
//   account: AWS_ACCOUNT_ID,
// });

app.synth();
