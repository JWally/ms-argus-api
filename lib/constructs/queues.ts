// lib/constructs/queues.ts
import { Construct } from 'constructs';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as actions from 'aws-cdk-lib/aws-cloudwatch-actions';
import { Duration } from 'aws-cdk-lib';

interface QueuesConstructProps {
  stackName: string;
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

    const { stackName, alarmsTopic } = props;

    // Dead Letter Queue for matching failures
    this.matchingDlq = new sqs.Queue(this, 'MatchingDLQ', {
      queueName: `${stackName}-matching-dlq`,
      retentionPeriod: Duration.days(14),
    });

    // Main matching queue - fingerprints to be processed
    this.matchingQueue = new sqs.Queue(this, 'MatchingQueue', {
      queueName: `${stackName}-matching`,
      visibilityTimeout: Duration.seconds(60), // Lambda timeout + buffer
      retentionPeriod: Duration.days(4),
      deadLetterQueue: {
        queue: this.matchingDlq,
        maxReceiveCount: 3,
      },
    });

    // Dead Letter Queue for profile update failures
    this.profileDlq = new sqs.Queue(this, 'ProfileDLQ', {
      queueName: `${stackName}-profile-dlq`,
      retentionPeriod: Duration.days(14),
    });

    // Profile update queue - writes to DynamoDB/Qdrant
    this.profileQueue = new sqs.Queue(this, 'ProfileQueue', {
      queueName: `${stackName}-profile`,
      visibilityTimeout: Duration.seconds(60),
      retentionPeriod: Duration.days(4),
      deadLetterQueue: {
        queue: this.profileDlq,
        maxReceiveCount: 3,
      },
    });

    // Alarms
    this.createQueueAlarms(this.matchingQueue, 'Matching', alarmsTopic);
    this.createQueueAlarms(this.profileQueue, 'Profile', alarmsTopic);
    this.createDlqAlarms(this.matchingDlq, 'MatchingDLQ', alarmsTopic);
    this.createDlqAlarms(this.profileDlq, 'ProfileDLQ', alarmsTopic);
  }

  private createQueueAlarms(queue: sqs.Queue, prefix: string, alarmsTopic: sns.ITopic) {
    // High backlog alarm
    const backlogAlarm = new cloudwatch.Alarm(this, `${prefix}QueueBacklog`, {
      metric: queue.metricApproximateNumberOfMessagesVisible({
        period: Duration.minutes(5),
        statistic: 'Average',
      }),
      threshold: 10000,
      evaluationPeriods: 2,
      alarmDescription: `${prefix} queue backlog > 10k messages`,
    });
    backlogAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));

    // Age of oldest message alarm (indicates stuck processing)
    const ageAlarm = new cloudwatch.Alarm(this, `${prefix}QueueAge`, {
      metric: queue.metricApproximateAgeOfOldestMessage({
        period: Duration.minutes(5),
        statistic: 'Maximum',
      }),
      threshold: 300, // 5 minutes
      evaluationPeriods: 2,
      alarmDescription: `${prefix} queue has messages older than 5 minutes`,
    });
    ageAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));
  }

  private createDlqAlarms(dlq: sqs.Queue, prefix: string, alarmsTopic: sns.ITopic) {
    // Any message in DLQ is concerning
    const dlqAlarm = new cloudwatch.Alarm(this, `${prefix}HasMessages`, {
      metric: dlq.metricApproximateNumberOfMessagesVisible({
        period: Duration.minutes(5),
        statistic: 'Sum',
      }),
      threshold: 1,
      evaluationPeriods: 1,
      alarmDescription: `${prefix} has messages - processing failures detected`,
    });
    dlqAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));
  }
}
