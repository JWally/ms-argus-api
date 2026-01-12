// lib/constructs/queues.ts
// AR-44: Uses centralized stage config for environment-specific values
import { Construct } from "constructs";
import * as sqs from "aws-cdk-lib/aws-sqs";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as sns from "aws-cdk-lib/aws-sns";
import * as actions from "aws-cdk-lib/aws-cloudwatch-actions";
import { Duration } from "aws-cdk-lib";
import { getStageConfig } from "../config";

interface QueuesConstructProps {
  stackName: string;
  stage: string;
  alarmsTopic: sns.ITopic;
}

/**
 * SQS Queues for Argus async processing
 * - Matching Queue: fingerprints waiting to be matched
 * - Profile Queue: profile updates to be written to DynamoDB/Qdrant
 */
export class QueuesConstruct extends Construct {
  public readonly matchingQueue: sqs.Queue;
  public readonly matchingDlq: sqs.Queue;
  public readonly profileQueue: sqs.Queue;
  public readonly profileDlq: sqs.Queue;

  constructor(scope: Construct, id: string, props: QueuesConstructProps) {
    super(scope, id);

    const { stackName, stage, alarmsTopic } = props;

    // AR-44: Use centralized stage config for all tunable values
    const config = getStageConfig(stage);

    // Dead Letter Queue for matching failures
    this.matchingDlq = new sqs.Queue(this, "MatchingDLQ", {
      queueName: `${stackName}-matching-dlq`,
      retentionPeriod: Duration.days(14),
    });

    // Main matching queue - fingerprints to be processed
    this.matchingQueue = new sqs.Queue(this, "MatchingQueue", {
      queueName: `${stackName}-matching`,
      visibilityTimeout: config.sqs.visibilityTimeout,
      retentionPeriod: config.sqs.retentionPeriod,
      deadLetterQueue: {
        queue: this.matchingDlq,
        maxReceiveCount: config.sqs.maxReceiveCount,
      },
    });

    // Dead Letter Queue for profile update failures
    this.profileDlq = new sqs.Queue(this, "ProfileDLQ", {
      queueName: `${stackName}-profile-dlq`,
      retentionPeriod: Duration.days(14),
    });

    // Profile update queue - writes to DynamoDB/Qdrant
    this.profileQueue = new sqs.Queue(this, "ProfileQueue", {
      queueName: `${stackName}-profile`,
      visibilityTimeout: config.sqs.visibilityTimeout,
      retentionPeriod: config.sqs.retentionPeriod,
      deadLetterQueue: {
        queue: this.profileDlq,
        maxReceiveCount: config.sqs.maxReceiveCount,
      },
    });

    // Alarms - AR-44: Pass config for thresholds
    this.createQueueAlarms(
      this.matchingQueue,
      "Matching",
      alarmsTopic,
      config.alarms.queue,
    );
    this.createQueueAlarms(
      this.profileQueue,
      "Profile",
      alarmsTopic,
      config.alarms.queue,
    );
    this.createDlqAlarms(this.matchingDlq, "MatchingDLQ", alarmsTopic);
    this.createDlqAlarms(this.profileDlq, "ProfileDLQ", alarmsTopic);
  }

  private createQueueAlarms(
    queue: sqs.Queue,
    prefix: string,
    alarmsTopic: sns.ITopic,
    alarmConfig: { backlogThreshold: number; messageAgeSeconds: number },
  ) {
    // High backlog alarm - AR-44: threshold from config
    const backlogAlarm = new cloudwatch.Alarm(this, `${prefix}QueueBacklog`, {
      metric: queue.metricApproximateNumberOfMessagesVisible({
        period: Duration.minutes(5),
        statistic: "Average",
      }),
      threshold: alarmConfig.backlogThreshold,
      evaluationPeriods: 2,
      alarmDescription: `${prefix} queue backlog > ${alarmConfig.backlogThreshold} messages`,
    });
    backlogAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));

    // Age of oldest message alarm - AR-44: threshold from config
    const ageAlarm = new cloudwatch.Alarm(this, `${prefix}QueueAge`, {
      metric: queue.metricApproximateAgeOfOldestMessage({
        period: Duration.minutes(5),
        statistic: "Maximum",
      }),
      threshold: alarmConfig.messageAgeSeconds,
      evaluationPeriods: 2,
      alarmDescription: `${prefix} queue has messages older than ${alarmConfig.messageAgeSeconds}s`,
    });
    ageAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));
  }

  private createDlqAlarms(
    dlq: sqs.Queue,
    prefix: string,
    alarmsTopic: sns.ITopic,
  ) {
    // Any message in DLQ is concerning
    const dlqAlarm = new cloudwatch.Alarm(this, `${prefix}HasMessages`, {
      metric: dlq.metricApproximateNumberOfMessagesVisible({
        period: Duration.minutes(5),
        statistic: "Sum",
      }),
      threshold: 1,
      evaluationPeriods: 1,
      alarmDescription: `${prefix} has messages - processing failures detected`,
    });
    dlqAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));
  }
}
