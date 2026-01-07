// lib/helpers/make-glue-table.ts
import * as glue from 'aws-cdk-lib/aws-glue';
import { Construct } from 'constructs';

/**
 * Creates a Glue JSON table for Firehose schema reference
 */
export const makeJsonTable = (
  conThis: Construct,
  scopeId: string,
  tableName: string,
  account: string,
  glueDbName: string,
  columns: glue.CfnTable.ColumnProperty[],
  glueDb: glue.CfnDatabase,
) => {
  const tbl = new glue.CfnTable(conThis, scopeId, {
    catalogId: account,
    databaseName: glueDbName,
    tableInput: {
      name: tableName,
      tableType: 'EXTERNAL_TABLE',
      parameters: {
        classification: 'json',
        compressionType: 'none',
        'projection.enabled': 'false',
      },
      storageDescriptor: {
        columns,
        inputFormat: 'org.apache.hadoop.mapred.TextInputFormat',
        outputFormat: 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat',
        serdeInfo: {
          serializationLibrary: 'org.openx.data.jsonserde.JsonSerDe',
          parameters: {},
        },
        location: `s3://dummy-location-not-used/`,
      },
    },
  });
  tbl.addDependency(glueDb);
  return tbl;
};

/**
 * Creates a Glue Parquet table with partition projection
 * - Assumes Hive-style layout: parquet/year=YYYY/month=MM/day=DD/hour=HH/
 * - Enables partition projection (no MSCK REPAIR needed)
 */
export const makeParquetProjectionTable = (
  conThis: Construct,
  scopeId: string,
  tableName: string,
  account: string,
  glueDbName: string,
  columns: glue.CfnTable.ColumnProperty[],
  glueDb: glue.CfnDatabase,
  bucketName: string,
  basePrefix = 'parquet/',
  ranges = { year: [2024, 2035] as [number, number] },
) => {
  const params: Record<string, string> = {
    'projection.enabled': 'true',
    'projection.year.type': 'integer',
    'projection.year.range': `${ranges.year[0]},${ranges.year[1]}`,
    'projection.month.type': 'integer',
    'projection.month.range': '1,12',
    'projection.month.digits': '2',
    'projection.day.type': 'integer',
    'projection.day.range': '1,31',
    'projection.day.digits': '2',
    'projection.hour.type': 'integer',
    'projection.hour.range': '0,23',
    'projection.hour.digits': '2',
    'storage.location.template':
      `s3://${bucketName}/${basePrefix}` + 'year=${year}/month=${month}/day=${day}/hour=${hour}/',
  };

  const tbl = new glue.CfnTable(conThis, scopeId, {
    catalogId: account,
    databaseName: glueDbName,
    tableInput: {
      name: tableName,
      tableType: 'EXTERNAL_TABLE',
      parameters: params,
      storageDescriptor: {
        location: `s3://${bucketName}/${basePrefix}`,
        columns,
        inputFormat: 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat',
        outputFormat: 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat',
        compressed: true,
        serdeInfo: {
          serializationLibrary: 'org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe',
          parameters: {},
        },
      },
      partitionKeys: [
        { name: 'year', type: 'int' },
        { name: 'month', type: 'int' },
        { name: 'day', type: 'int' },
        { name: 'hour', type: 'int' },
      ],
    },
  });

  tbl.addDependency(glueDb);
  return tbl;
};
