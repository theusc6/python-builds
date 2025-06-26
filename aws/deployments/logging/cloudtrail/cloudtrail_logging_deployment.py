# pylint: disable=C0301:too-many-lines
""" 
Splunk Kinesis Integration for CloudTrail

This module deploys the necessary infrastructure for integrating AWS CloudTrail logs with Splunk
via Kinesis Data Firehose. It covers the creation and configuration of
required AWS resources like S3 buckets, Kinesis Firehose Streams, IAM roles, and policies.

Key Features:
- Creation of a dedicated S3 bucket for the Kinesis processor.
- Establishment of a KMS key for data encryption and its management.
- Setup of an IAM role and policy for the Firehose stream.
- Configuration of the Kinesis Data Firehose to relay data to a specified Splunk endpoint.

!This script must be ran first in a two-part series! 

Then, a separate script, "cloudwatch_configure_cross-account_subscription_filter.py" must be
ran on the originating account. That script will configure the subscription filter used to 
send logs to the infrastructure created by this script. Once both scripts have ran,
logging will be configured successfully.

Usage:
    Run the script and provide required command-line arguments:
    - AWS profile name for SSO login (`-p` or `--profile`)
    - AWS region where resources will be created (`-r` or `--region`)
    - AWS account ID for the delegated administrator account (`-a` or `--account_id`)
"""

import argparse
import io
import zipfile
import time
import json
import boto3
from botocore.exceptions import ClientError

CLOUDWATCH_LOG_GROUP = "/aws/kinesisfirehose/splunk/cloudtrail"

def create_s3_bucket(session, bucket_name, account_id, region):
    """
    This function creates an Amazon S3 bucket with a specified name, policy, tagging,
    versioning configuration, public access block configuration, and lifecycle policy.

    Parameters:
    session (boto3.Session): An AWS session object created by Boto3.
    bucket_name (str): The name of the S3 bucket to be created.
    account_id (str): The AWS account ID in which the S3 bucket will be created.
    region (str): The AWS region where the S3 bucket will be created.

    Returns:
    None
    """
    s3_client = session.client('s3')
    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
        {
            'Sid': 'RequireSSLOnly',
            'Effect': 'Deny',
            'Principal': '*',
            'Action': 's3:*',
            'Resource': [
                f'arn:aws:s3:::{bucket_name}/*',
                f'arn:aws:s3:::{bucket_name}'
            ],
            'Condition': {
                'Bool': {
                    'aws:SecureTransport': 'false'
                }
            }
        }

        ]
    }

    try:
        s3_client.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={'LocationConstraint': region}
        )
        print(f"{bucket_name} has now been created.")
    except ClientError as client_error:
        if client_error.response['Error']['Code'] == 'BucketAlreadyOwnedByYou':
            print(f"Bucket {bucket_name} already exists.")
        else:
            print(f"An error occurred while creating the bucket: "
                  f"{client_error.response['Error']['Message']}")
            return

    try:
        s3_client.put_bucket_policy(
            Bucket=bucket_name,
            Policy=json.dumps(bucket_policy)
        )
        print(f"SSL is now required for bucket {bucket_name}.")
    except ClientError as client_error:
        print(f"An error occurred while applying the bucket policy: "
              f"{client_error.response['Error']['Message']}")

    try:
        s3_client.put_bucket_tagging(
            Bucket=bucket_name,
            Tagging={'TagSet': [{'Key': 'Category', 'Value': 'Security'}]}
        )
        print(f"Tags have been applied to bucket {bucket_name}.")
    except ClientError as client_error:
        print(f"An error occurred while applying bucket tags: "
              f"{client_error.response['Error']['Message']}")

    try:
        s3_client.put_bucket_versioning(
                Bucket=bucket_name,
                VersioningConfiguration={
                    'Status': 'Enabled'
                }
            )
        print(f"Versioning is enabled for for {bucket_name}.")
    except ClientError as client_error:
        print(f"An error occurred while enabling bucket versioning: "
              f"{client_error.response['Error']['Message']}")

    try:
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        print(f"Public access is blocked for {bucket_name}.")
    except ClientError as client_error:
        print(f"An error occurred while blocking public access: "
              f"{client_error.response['Error']['Message']}")

    lifecycle_policy = {
        'Rules': [
            {
                'ID': 'securityhub-s3.13-default-lifecycle-policy',
                'Status': 'Enabled',
                'Filter': {
                    'Prefix': ''
                },
                'Transitions': [
                    {
                        'Days': 0,
                        'StorageClass': 'INTELLIGENT_TIERING'
                    }
                ],
                'NoncurrentVersionTransitions': [
                    {
                        'NoncurrentDays': 30,
                        'StorageClass': 'GLACIER_IR'
                    }
                ],
                'Expiration': {
                    'ExpiredObjectDeleteMarker': True
                },
                'NoncurrentVersionExpiration': {
                    'NoncurrentDays': 180,
                    'NewerNoncurrentVersions':1
                },
                'AbortIncompleteMultipartUpload': {
                    'DaysAfterInitiation': 30
                }
            }
        ]
    }

    log_bucket_name= f"securityhub-s3.9accesslogging-{account_id}-{region}"

    try:
        s3_client.put_bucket_lifecycle_configuration(
            Bucket=bucket_name,
            LifecycleConfiguration=lifecycle_policy
        )
        print(f"Applied bucket lifecycle policy for bucket {bucket_name}.")
    except ClientError as client_error:
        print(f"An error occurred while applying lifecycle policy: "
              f"{client_error.response['Error']['Message']}")

    if 'securityhub-s3.9accesslogging' not in bucket_name:
        try:
            s3_client.put_bucket_logging(
                Bucket=bucket_name,
                BucketLoggingStatus={
                    'LoggingEnabled': {
                        'TargetBucket': log_bucket_name,
                        'TargetPrefix': f"{bucket_name}/"
                    }
                }
            )
            print(f"Enabled logging for bucket {bucket_name}. "
                  f"Logging to {log_bucket_name}.")
        except ClientError as error:
            print(f"An error occurred: {error.response['Error']['Message']}")

def create_kms_key(session, key_alias, region, account_id):
    """
    This function checks if a KMS key with a given alias exists.
    If it does not exist, the function creates a new KMS key with that alias.

    Parameters:
    session (boto3.Session): An AWS session object created by Boto3.
    key_alias (str): The alias for the KMS key.
    account_id (str): The AWS account ID in which the KMS key will be created.
    region (str): The AWS region where the KMS key will be created.

    Returns:
    str: The ARN of the KMS key.
    """
    kms_client = session.client('kms')

    # List all key aliases
    paginator = kms_client.get_paginator('list_aliases')

    for page in paginator.paginate():
        for alias in page['Aliases']:
            if alias['AliasName'] == key_alias:
                print(f"Key with alias {key_alias} already exists.")
                # Return the ARN of the existing key
                return f"arn:aws:kms:{region}:{account_id}:key/{alias['TargetKeyId']}"

    # If no key with the given alias exists, create a new one
    print(f"Creating a new key with alias {key_alias}...")

    policy = {
            "Version": "2012-10-17",
            "Id": "key-consolepolicy-3",
            "Statement": [
                {
                    "Sid": "Allow actions for CMK",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": [
                            "sns.amazonaws.com",
                            "logs.amazonaws.com",
                            "events.amazonaws.com",
                            "s3.amazonaws.com", 
                            "kinesis.amazonaws.com"
                        ]
                    },
                    "Action": "kms:*",
                    "Resource": "*"
                },
                {
                    "Sid": "Allow Amazon Kinesis Firehose/Events/Cloudwatch to use the key",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": [
                            "logs.amazonaws.com",
                            "events.amazonaws.com",
                            "firehose.amazonaws.com"

                        ]
                    },
                    "Action": "kms:*",
                    "Resource": "*"
                },
                {
                    "Sid": "Allow full control to root user",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "*"
                    },
                    "Action": "kms:*",
                    "Resource": "*"
                }
            ]
        }

    retries = 0
    while retries < 3:
        try:
            response = kms_client.create_key(
                Policy=json.dumps(policy),
                Description='Key for Amazon CloudTrail & Splunk Logging',
                KeyUsage='ENCRYPT_DECRYPT',
                Origin='AWS_KMS',
                BypassPolicyLockoutSafetyCheck=False
            )
            kms_key_id = response['KeyMetadata']['KeyId']

            kms_client.create_alias(
                AliasName=key_alias,
                TargetKeyId=kms_key_id
            )

            kms_client.tag_resource(
                KeyId=kms_key_id,
                Tags=[{'TagKey': 'Category', 'TagValue': 'Security'}]
            )

            try:
                kms_client.enable_key_rotation(KeyId=kms_key_id)
                print(f"Enabled key rotation for key {kms_key_id}")
            except ClientError as client_error:
                print(f"An error occurred while enabling key rotation: "
                    f"{client_error.response['Error']['Message']}")

            return f"arn:aws:kms:{region}:{account_id}:key/{kms_key_id}"

        except ClientError as client_error:
            if client_error.response['Error']['Code'] == 'MalformedPolicyDocumentException':
                print(f"An error occurred while creating the KMS Key, retrying: "
                    f"{client_error.response['Error']['Message']}")
                retries += 1
                time.sleep(10)  # Wait for 10 seconds before retrying
            else:
                print(f"An error occurred while creating the KMS Key: "
                    f"{client_error.response['Error']['Message']}")
                raise client_error

    raise RuntimeError('Failed to create KMS key after 3 attempts.')

def enable_rotation_if_not_set(session, key_id):
    """
    This function enables key rotation for a specified KMS key if it's not already enabled.

    Parameters:
    session (boto3.Session): An AWS session object created by Boto3.
    key_id (str): The ID of the KMS key for which to enable rotation.

    Returns:
    None
    """
    kms_client = session.client('kms')
    try:
        # Get key rotation status
        response = kms_client.get_key_rotation_status(KeyId=key_id)
        # If rotation is not enabled, enable it
        if not response['KeyRotationEnabled']:
            kms_client.enable_key_rotation(KeyId=key_id)
            print(f"Enabled key rotation for key {key_id}")
        else:
            print(f"Key rotation is already enabled for key {key_id}")
    except ClientError as client_error:
        print(f"An error occurred while checking/enabling key rotation: "
              f"{client_error.response['Error']['Message']}")

def create_firehose_policy(aws_params, key_alias, lambda_arn):
    """
    Creates an IAM policy with permissions for KMS keys associated with S3 and Kinesis.

    Parameters:
    - session (boto3.Session): An active boto3 session.
    - key_alias (str): The alias of the KMS key for Kinesis.
    - bucket_name (str): The name of the S3 bucket involved in the policy.
    - account_id (str): The AWS account ID.
    - region (str): The AWS region where resources are located.

    """

    session = aws_params['session']
    account_id = aws_params['account_id']
    region = aws_params['region']
    bucket_name = aws_params['bucket_name']

    iam_client = session.client('iam')

    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "KMS",
                "Effect": "Allow",
                "Action": [
                    "kms:Decrypt",
                    "kms:GenerateDataKey"
                ],
                "Resource": [
                    "*"
                ],
                "Condition": {
                    "StringLike": {
                        "kms:RequestAlias": [
                            "alias/aws/kinesis",
                            "alias/aws/s3",
                            f"{key_alias}"
                        ]
                    }
                }
            },
            {
                "Sid": "S3",
                "Effect": "Allow",
                "Action": [
                    "s3:PutObject",
                    "s3:GetObject",
                    "s3:ListBucketMultipartUploads",
                    "s3:AbortMultipartUpload",
                    "s3:ListBucket",
                    "s3:GetBucketLocation"
                ],
                "Resource": [
                    f"arn:aws:s3:::{bucket_name}/*",
                    f"arn:aws:s3:::{bucket_name}"
                ]
            },
            {
                "Sid": "KinesisFirehose",
                "Effect": "Allow",
                "Action": [
                    "firehose:List*",
                    "firehose:Describe*",
                    "firehose:Put*"
                ],
                "Resource": [
                    f"arn:aws:firehose:{region}:{account_id}:deliverystream"
                    f"/splunk-cloudtrail-processor-firehose-{account_id}-{region}"
                ]
            },
            {
                "Sid": "Cloudwatch",
                "Effect": "Allow",
                "Action": [
                    "logs:PutLogEvents"
                ],
                "Resource": [
                    f"arn:aws:logs:{region}:{account_id}:log-group:"
                    f"/aws/kinesisfirehose/splunk/cloudtrail:log-stream:*"
                ]
            },
            {
                "Sid": "Lambda",
                "Effect": "Allow",
                "Action": [
                    "lambda:InvokeFunction",
                    "lambda:GetFunctionConfiguration"
                ],
                "Resource": [
                    f"{lambda_arn}*"
                ]
            }
        ]
    }
    policy_name = f"policy-splunk-cloudtrail-processor-{account_id}-{region}"

    try:
        response = iam_client.create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy_document)
        )
        return response['Policy']['Arn']
    except ClientError as client_error:
        if client_error.response['Error']['Code'] == 'EntityAlreadyExists':
            print("The IAM policy already exists. Retrieving its ARN...")
            try:
                policy_arn = (
                    f"arn:aws:iam::{account_id}:policy/{policy_name}"
                )
                existing_policy = iam_client.get_policy(PolicyArn=policy_arn)
                return existing_policy['Policy']['Arn']
            except ClientError as retrieve_error:
                print(f"An error occurred while retrieving the ARN of "
                      f"the existing policy: {retrieve_error}")
                return None
        else:
            print(f"An error occurred: {client_error}")
            return None

def create_firehose_role(session, account_id, region, custom_policy_arn):
    """
    Create or update an IAM role for Kinesis Firehose with necessary policies.
    Simplified by directly attaching policies without checking existing ones.
    """
    # Constants for the role and policies
    role_name = f'role-splunk-cloudtrail-processor-{account_id}-{region}'
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "firehose.amazonaws.com"
                },
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {
                        "sts:ExternalId": "044370118492"
                    }
                }
            },
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": [
                        "firehose.amazonaws.com",
                        "lambda.amazonaws.com"
                    ]
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }

    policies = [
        #The below are commented out as they are taken care of in the custom policy.
        #However, they are left in the code for reference and testing purposes.
        #Policies are looped below for application, so to apply or add new ones, simply
        #add them here in the "policies" list.

        #"arn:aws:iam::aws:policy/CloudWatchLogsFullAccess",
        #"arn:aws:iam::aws:policy/AmazonKinesisFullAccess",
        #"arn:aws:iam::aws:policy/AmazonKinesisFirehoseFullAccess",
        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        custom_policy_arn  # Custom policy ARN
    ]

    # Create an IAM client
    iam = session.client('iam')

    # Create the role (if it doesn't exist) or get its ARN
    try:
        # Attempt to create the role
        response = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description="Role for Kinesis Firehose"
        )
        role_arn = response['Role']['Arn']
        print(f"Created role {role_name} with ARN: {role_arn}")
    except iam.exceptions.EntityAlreadyExistsException:
        # If the role already exists, just retrieve its ARN
        role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
        print(f"Role {role_name} already exists. Using ARN: {role_arn}")

    # Attach policies to the role
    for policy_arn in policies:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        print(f"Attached policy {policy_arn} to role {role_name}")

    print("Waiting for the role and policies to propagate...")
    time.sleep(30)

    return role_arn

def create_lambda_function(session, function_name, role_arn):
    """
    This function creates an AWS Lambda function.
    """
    lambda_client = session.client('lambda')

    blueprint_code =     '''
# Copyright 2014, Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Amazon Software License (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#  http://aws.amazon.com/asl/
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.

"""
For processing data sent to Firehose by Cloudwatch Logs subscription filters.

Cloudwatch Logs sends to Firehose records that look like this:

{
  "messageType": "DATA_MESSAGE",
  "owner": "123456789012",
  "logGroup": "log_group_name",
  "logStream": "log_stream_name",
  "subscriptionFilters": [
    "subscription_filter_name"
  ],
  "logEvents": [
    {
      "id": "01234567890123456789012345678901234567890123456789012345",
      "timestamp": 1510109208016,
      "message": "log message 1"
    },
    {
      "id": "01234567890123456789012345678901234567890123456789012345",
      "timestamp": 1510109208017,
      "message": "log message 2"
    }
    ...
  ]
}

The data is additionally compressed with GZIP.

The code below will:

1) Gunzip the data
2) Parse the json
3) Set the result to ProcessingFailed for any record whose messageType is not DATA_MESSAGE, thus redirecting them to the
   processing error output. Such records do not contain any log events. You can modify the code to set the result to
   Dropped instead to get rid of these records completely.
4) For records whose messageType is DATA_MESSAGE, extract the individual log events from the logEvents field, and pass
   each one to the transformLogEvent method. You can modify the transformLogEvent method to perform custom
   transformations on the log events.
5) Concatenate the result from (4) together and set the result as the data of the record returned to Firehose. Note that
   this step will not add any delimiters. Delimiters should be appended by the logic within the transformLogEvent
   method.
6) Any individual record exceeding 6,000,000 bytes in size after decompression, processing and base64-encoding is marked
   as Dropped, and the original record is split into two and re-ingested back into Firehose or Kinesis. The re-ingested
   records should be about half the size compared to the original, and should fit within the size limit the second time
   round.
7) When the total data size (i.e. the sum over multiple records) after decompression, processing and base64-encoding
   exceeds 6,000,000 bytes, any additional records are re-ingested back into Firehose or Kinesis.
8) The retry count for intermittent failures during re-ingestion is set 20 attempts. If you wish to retry fewer number
   of times for intermittent failures you can lower this value.

                                              ***IMPORTANT NOTE***
When using this blueprint, it is highly recommended to change the Kinesis Firehose Lambda setting for buffer size to
256KB to avoid 6MB Lambda limit.
"""

import base64
import json
import gzip
import boto3


def transformLogEvent(log_event):
    try:
        # Attempt to load the message as a JSON object
        message = json.loads(log_event['message'])
        # Convert the message back to a JSON string with formatting
        # Ensuring it is a properly formatted JSON object per line
        transformed_message = json.dumps(message)
    except json.JSONDecodeError:
        # If there's a JSON decoding error, just return the raw message
        transformed_message = log_event['message']
    # Append a newline character to separate this event in the output
    return transformed_message + '\n'


def processRecords(records):
    for r in records:
        data = loadJsonGzipBase64(r['data'])
        recId = r['recordId']
        # CONTROL_MESSAGE are sent by CWL to check if the subscription is reachable.
        # They do not contain actual data.
        if data['messageType'] == 'CONTROL_MESSAGE':
            yield {
                'result': 'Dropped',
                'recordId': recId
            }
        elif data['messageType'] == 'DATA_MESSAGE':
            joinedData = ''.join([transformLogEvent(e) for e in data['logEvents']])
            dataBytes = joinedData.encode("utf-8")
            encodedData = base64.b64encode(dataBytes).decode('utf-8')
            yield {
                'data': encodedData,
                'result': 'Ok',
                'recordId': recId
            }
        else:
            yield {
                'result': 'ProcessingFailed',
                'recordId': recId
            }

def splitCWLRecord(cwlRecord):
    """
    Splits one CWL record into two, each containing half the log events.
    Serializes and compreses the data before returning. That data can then be
    re-ingested into the stream, and it'll appear as though they came from CWL
    directly.
    """
    logEvents = cwlRecord['logEvents']
    mid = len(logEvents) // 2
    rec1 = {k:v for k, v in cwlRecord.items()}
    rec1['logEvents'] = logEvents[:mid]
    rec2 = {k:v for k, v in cwlRecord.items()}
    rec2['logEvents'] = logEvents[mid:]
    return [gzip.compress(json.dumps(r).encode('utf-8')) for r in [rec1, rec2]]

def putRecordsToFirehoseStream(streamName, records, client, attemptsMade, maxAttempts):
    failedRecords = []
    codes = []
    errMsg = ''
    # if put_record_batch throws for whatever reason, response['xx'] will error out, adding a check for a valid
    # response will prevent this
    response = None
    try:
        response = client.put_record_batch(DeliveryStreamName=streamName, Records=records)
    except Exception as e:
        failedRecords = records
        errMsg = str(e)

    # if there are no failedRecords (put_record_batch succeeded), iterate over the response to gather results
    if not failedRecords and response and response['FailedPutCount'] > 0:
        for idx, res in enumerate(response['RequestResponses']):
            # (if the result does not have a key 'ErrorCode' OR if it does and is empty) => we do not need to re-ingest
            if not res.get('ErrorCode'):
                continue

            codes.append(res['ErrorCode'])
            failedRecords.append(records[idx])

        errMsg = 'Individual error codes: ' + ','.join(codes)

    if failedRecords:
        if attemptsMade + 1 < maxAttempts:
            print('Some records failed while calling PutRecordBatch to Firehose stream, retrying. %s' % (errMsg))
            putRecordsToFirehoseStream(streamName, failedRecords, client, attemptsMade + 1, maxAttempts)
        else:
            raise RuntimeError('Could not put records after %s attempts. %s' % (str(maxAttempts), errMsg))


def putRecordsToKinesisStream(streamName, records, client, attemptsMade, maxAttempts):
    failedRecords = []
    codes = []
    errMsg = ''
    # if put_records throws for whatever reason, response['xx'] will error out, adding a check for a valid
    # response will prevent this
    response = None
    try:
        response = client.put_records(StreamName=streamName, Records=records)
    except Exception as e:
        failedRecords = records
        errMsg = str(e)

    # if there are no failedRecords (put_record_batch succeeded), iterate over the response to gather results
    if not failedRecords and response and response['FailedRecordCount'] > 0:
        for idx, res in enumerate(response['Records']):
            # (if the result does not have a key 'ErrorCode' OR if it does and is empty) => we do not need to re-ingest
            if not res.get('ErrorCode'):
                continue

            codes.append(res['ErrorCode'])
            failedRecords.append(records[idx])

        errMsg = 'Individual error codes: ' + ','.join(codes)

    if failedRecords:
        if attemptsMade + 1 < maxAttempts:
            print('Some records failed while calling PutRecords to Kinesis stream, retrying. %s' % (errMsg))
            putRecordsToKinesisStream(streamName, failedRecords, client, attemptsMade + 1, maxAttempts)
        else:
            raise RuntimeError('Could not put records after %s attempts. %s' % (str(maxAttempts), errMsg))


def createReingestionRecord(isSas, originalRecord, data=None):
    if data is None:
        data = base64.b64decode(originalRecord['data'])
    r = {'Data': data}
    if isSas:
        r['PartitionKey'] = originalRecord['kinesisRecordMetadata']['partitionKey']
    return r


def loadJsonGzipBase64(base64Data):
    return json.loads(gzip.decompress(base64.b64decode(base64Data)))


def lambda_handler(event, context):
    isSas = 'sourceKinesisStreamArn' in event
    streamARN = event['sourceKinesisStreamArn'] if isSas else event['deliveryStreamArn']
    region = streamARN.split(':')[3]
    streamName = streamARN.split('/')[1]
    records = list(processRecords(event['records']))
    projectedSize = 0
    recordListsToReingest = []

    for idx, rec in enumerate(records):
        originalRecord = event['records'][idx]

        if rec['result'] != 'Ok':
            continue

        # If a single record is too large after processing, split the original CWL data into two, each containing half
        # the log events, and re-ingest both of them (note that it is the original data that is re-ingested, not the 
        # processed data). If it's not possible to split because there is only one log event, then mark the record as
        # ProcessingFailed, which sends it to error output.
        if len(rec['data']) > 6000000:
            cwlRecord = loadJsonGzipBase64(originalRecord['data'])
            if len(cwlRecord['logEvents']) > 1:
                rec['result'] = 'Dropped'
                recordListsToReingest.append(
                    [createReingestionRecord(isSas, originalRecord, data) for data in splitCWLRecord(cwlRecord)])
            else:
                rec['result'] = 'ProcessingFailed'
                print(('Record %s contains only one log event but is still too large after processing (%d bytes), ' +
                       'marking it as %s') % (rec['recordId'], len(rec['data']), rec['result']))
            del rec['data']
        else:
            projectedSize += len(rec['data']) + len(rec['recordId'])
            # 6000000 instead of 6291456 to leave ample headroom for the stuff we didn't account for
            if projectedSize > 6000000:
                recordListsToReingest.append([createReingestionRecord(isSas, originalRecord)])
                del rec['data']
                rec['result'] = 'Dropped'

    # call putRecordBatch/putRecords for each group of up to 500 records to be re-ingested
    if recordListsToReingest:
        recordsReingestedSoFar = 0
        client = boto3.client('kinesis' if isSas else 'firehose', region_name=region)
        maxBatchSize = 500
        flattenedList = [r for sublist in recordListsToReingest for r in sublist]
        for i in range(0, len(flattenedList), maxBatchSize):
            recordBatch = flattenedList[i:i + maxBatchSize]
            # last argument is maxAttempts
            args = [streamName, recordBatch, client, 0, 20]
            if isSas:
                putRecordsToKinesisStream(*args)
            else:
                putRecordsToFirehoseStream(*args)
            recordsReingestedSoFar += len(recordBatch)
            print('Reingested %d/%d' % (recordsReingestedSoFar, len(flattenedList)))

    print('%d input records, %d returned as Ok or ProcessingFailed, %d split and re-ingested, %d re-ingested as-is' % (
        len(event['records']),
        len([r for r in records if r['result'] != 'Dropped']),
        len([l for l in recordListsToReingest if len(l) > 1]),
        len([l for l in recordListsToReingest if len(l) == 1])))

    return {'records': records}
    '''

    function_code = blueprint_code.encode()

    zip_stream = io.BytesIO()

    # Create a ZIP archive
    with zipfile.ZipFile(zip_stream, mode='w') as zipf:
        # Add the script as a file to the ZIP archive
        zipf.writestr('lambda_function.py', function_code)

    # Get the content of the ZIP archive as bytes
    zip_content = zip_stream.getvalue()

    try:
        response = lambda_client.create_function(
            FunctionName=function_name,
            Runtime='python3.11',
            Role=role_arn,
            Handler="lambda_function.lambda_handler",
            Code={
                'ZipFile': zip_content  # Provide the ZIP content here
            },
            Description=('An Amazon Kinesis Firehose stream processor that extracts individual '
                        'log events from records sent by Cloudwatch Logs subscription filters.'),
            Timeout=900, #This may need to be adjusted based on environment size
            MemorySize=1024, #This may need to be adjusted based on environment size
            Tags={
                'Category': 'Security'
            }
        )
        print(f"Lambda function {function_name} created successfully.")
        return response['FunctionArn']  # Return the ARN of the created Lambda function

    except lambda_client.exceptions.ClientError as client_error:
        print(f"Error creating Lambda function: {client_error}")
        return None

def create_firehose_stream(aws_params, endpoint_url, hec_token, lambda_arn, role_arn):
    """
    Create a Kinesis Data Firehose delivery stream.
    
    Parameters:
    - stream_name: Name of the Firehose stream.
    - s3_bucket: Destination S3 bucket for the Firehose.
    - s3_prefix: Prefix for the S3 destination.
    
    Returns:
    - Response from the create_delivery_stream Boto3 call.
    """
    session = aws_params['session']
    account_id = aws_params['account_id']
    region = aws_params['region']
    bucket_name = aws_params['bucket_name']

    firehose_client = session.client('firehose')

    stream_name = f"splunk-cloudtrail-processor-firehose-{account_id}-{region}"

    try:
        firehose_client.create_delivery_stream(
            DeliveryStreamName=stream_name,
            DeliveryStreamType='DirectPut',
            DeliveryStreamEncryptionConfigurationInput={
                "KeyType": "AWS_OWNED_CMK"
            },
            SplunkDestinationConfiguration={
                'HECEndpoint': endpoint_url,
                'HECEndpointType': 'Raw',
                'HECToken': hec_token,
                'HECAcknowledgmentTimeoutInSeconds': 180,
                'RetryOptions': {
                    'DurationInSeconds': 300
                },
                "ProcessingConfiguration": {
                    "Enabled": True,
                    "Processors": [
                        {
                            "Type": "Lambda",
                            "Parameters": [
                                {
                                    "ParameterName": "LambdaArn",
                                    "ParameterValue": lambda_arn
                                },
                                {
                                    "ParameterName": "RoleArn",
                                    "ParameterValue": role_arn
                                },
                            ]
                        },
                    ]
                },
                'S3BackupMode': 'FailedEventsOnly',  # Choose between 
                                                     #'FailedEventsOnly' or 'AllEvents'
                'S3Configuration': {
                    'RoleARN': role_arn,  # Replace with actual Role ARN
                    'BucketARN': f'arn:aws:s3:::{bucket_name}',
                    'Prefix': "/backups",
                    'ErrorOutputPrefix': "/errors",
                    'BufferingHints': {
                        'SizeInMBs': 100,
                        'IntervalInSeconds': 300
                    },
                    'CompressionFormat': 'UNCOMPRESSED',
                    'CloudWatchLoggingOptions': {
                        'Enabled': True,
                        'LogGroupName': CLOUDWATCH_LOG_GROUP,
                        'LogStreamName': 'BackupDelivery'
                    }
                },
                'CloudWatchLoggingOptions': {
                    'Enabled': True,
                    'LogGroupName': CLOUDWATCH_LOG_GROUP,
                    'LogStreamName': 'DestinationDelivery'
                }
            },
             Tags=[
                {
                    'Key': 'Category',
                    'Value': 'Security'
                },
            ]
        )
        # Describe the stream to get its ARN
        firehose_client.describe_delivery_stream(DeliveryStreamName=stream_name)
        #arn = response['DeliveryStreamDescription']['DeliveryStreamARN']
        firehose_arn = f"arn:aws:firehose:{region}:{account_id}:deliverystream/{stream_name}"
        print("Waiting for the Firehose Delivery Stream(s) to propagate...")
        time.sleep(180)
        return firehose_arn

    except ClientError as client_error:
        print(f"An error occurred: {client_error}")
        return None

def create_encrypted_log_group_with_streams(session, region, kms_key_arn):
    """
    Create an encrypted CloudWatch Log group with two log streams and a specified retention period.
    """
    logs_client = session.client('logs', region_name=region)
    log_group_name = CLOUDWATCH_LOG_GROUP
    retention_days = 365

    try:
        # Create the log group with KMS encryption
        logs_client.create_log_group(
            logGroupName=log_group_name,
            kmsKeyId=kms_key_arn
        )
        print(f"Log group {log_group_name} created successfully with KMS encryption.")

        # Set the retention policy for the log group
        logs_client.put_retention_policy(
            logGroupName=log_group_name,
            retentionInDays=retention_days
        )
        print(f"Retention policy for log group {log_group_name} set to {retention_days} days.")

    except logs_client.exceptions.ResourceAlreadyExistsException:
        print(f"Log group {log_group_name} already exists. Continuing with existing log group.")
    except ClientError as client_error:
        print(f"An error occurred while processing log group {log_group_name}: {client_error}")

    destination_stream = 'DestinationDelivery'
    backup_stream = 'BackupDelivery'

    # Create the two log streams within the log group
    for log_stream_name in [destination_stream, backup_stream]:
        try:
            logs_client.create_log_stream(
                logGroupName=log_group_name,
                logStreamName=log_stream_name
            )
            print(f"Log stream {log_stream_name} created successfully "
                  f"in log group {log_group_name}.")

        except logs_client.exceptions.ResourceAlreadyExistsException:
            print(f"Log stream {log_stream_name} already exists in log "
                  f"group {log_group_name}. Skipping creation.")
        except ClientError as client_error:
            print(f"An error occurred while processing "
                  f"log stream {log_stream_name}: {client_error}")

def create_cloudwatch_policy(aws_params):
    """
    Creates an IAM policy with permissions for KMS keys associated with S3 and Kinesis.

    Parameters:
    - session (boto3.Session): An active boto3 session.
    - key_alias (str): The alias of the KMS key for Kinesis.
    - bucket_name (str): The name of the S3 bucket involved in the policy.
    - account_id (str): The AWS account ID.
    - region (str): The AWS region where resources are located.

    """

    session = aws_params['session']
    account_id = aws_params['account_id']
    region = aws_params['region']
    iam_client = session.client('iam')

    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "KinesisFirehose",
                "Effect": "Allow",
                "Action": [
                    "firehose:List*",
                    "firehose:Describe*",
                    "firehose:Put*",
                    "firehose:*"
                ],
                "Resource": [
                    f"arn:aws:firehose:{region}:{account_id}:*"
                ]
            },
        ]
    }
    policy_name = f"policy-splunk-cloudwatch-destination-{account_id}-{region}"

    try:
        response = iam_client.create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy_document)
        )
        return response['Policy']['Arn']
    except ClientError as client_error:
        if client_error.response['Error']['Code'] == 'EntityAlreadyExists':
            print("The IAM policy already exists. Retrieving its ARN...")
            try:
                policy_arn = (
                    f"arn:aws:iam::{account_id}:policy/{policy_name}"
                )
                existing_policy = iam_client.get_policy(PolicyArn=policy_arn)
                return existing_policy['Policy']['Arn']
            except ClientError as retrieve_error:
                print(f"An error occurred while retrieving the ARN of "
                      f"the existing policy: {retrieve_error}")
                return None
        else:
            print(f"An error occurred: {client_error}")
            return None

def create_cloudwatch_role(session, account_id, region, custom_policy_arn):
    """
    Create or update an IAM role for Kinesis Firehose with necessary policies.
    Simplified by directly attaching policies without checking existing ones.
    """
    # Constants for the role and policies
    role_name = f'role-splunk-cloudwatch-destination-{account_id}-{region}'
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": f"logs.{region}.amazonaws.com"
                },
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringLike": {
                        "aws:SourceArn": [
                            f"arn:aws:logs:{region}:044370118492:*",
                            f"arn:aws:logs:{region}:{account_id}:*"
                        ]
                    }
                }
            }
        ]
    }
    policies = [
        #The below are commented out as they are taken care of in the custom policy.
        #However, they are left in the code for reference and testing purposes.
        #Policies are looped below for application, so to apply or add new ones, simply
        #add them here in the "policies" list.

        #"arn:aws:iam::aws:policy/CloudWatchLogsFullAccess",
        #"arn:aws:iam::aws:policy/AmazonKinesisFullAccess",
        #"arn:aws:iam::aws:policy/AmazonKinesisFirehoseFullAccess",

        custom_policy_arn  # Custom policy ARN
    ]

    # Create an IAM client
    iam = session.client('iam')

    # Create the role (if it doesn't exist) or get its ARN
    try:
        # Attempt to create the role
        response = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description="Role for Kinesis Firehose"
        )
        cloudwatch_role_arn = response['Role']['Arn']
        print(f"Created role {role_name} with ARN: {cloudwatch_role_arn}")
    except iam.exceptions.EntityAlreadyExistsException:
        # If the role already exists, just retrieve its ARN
        cloudwatch_role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
        print(f"Role {role_name} already exists. Using ARN: {cloudwatch_role_arn}")

    # Attach policies to the role
    for policy_arn in policies:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        print(f"Attached policy {policy_arn} to role {role_name}")

    print("Waiting for the role and policies to propagate...")
    time.sleep(30)

    return cloudwatch_role_arn


def create_cloudwatch_logs_destination(session, account_id, region, firehose_arn,
                                       cloudwatch_role_arn):
    """
    Create a CloudWatch Logs destination.
    :param destination_name: The name of the CloudWatch Logs destination.
    :param target_arn: The ARN of the physical resource where the log events
        are delivered (e.g., Kinesis stream).
    :param role_arn: The ARN of the IAM role that permits CloudWatch Logs to
        send data to the target.
    """
    # Initialize the CloudWatch Logs client
    logs_client = session.client('logs')
    destination_name=f"splunk-cloudtrail-processor-destination-{account_id}-{region}"
    print(destination_name)
    print(firehose_arn)
    print(cloudwatch_role_arn)
    try:
        # Create the destination
        logs_client.put_destination(
            destinationName=destination_name,
            targetArn=firehose_arn,
            roleArn=cloudwatch_role_arn
        )
        print("Destination created successfully.")
        return destination_name
    except logs_client.exceptions.ClientError as error:
        print(f"An error occurred: {error}")
        raise

def put_destination_access_policy(session, account_id, region, destination_name):
    """
    Create or update a policy for a CloudWatch Logs destination.

    :param account_id: The AWS account ID where the destination is located.
    :param region: The AWS region where the destination is located.
    :param destination_name: The name of the CloudWatch Logs destination.
    """
    # Initialize the CloudWatch Logs client
    logs_client = session.client('logs')

    # Construct the destination ARN
    destination_arn = f"arn:aws:logs:{region}:{account_id}:destination:{destination_name}"

    # Define the policy document
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "",
                "Effect": "Allow",
                "Principal": {
                    "AWS": "*"
                },
                "Action": "logs:PutSubscriptionFilter",
                "Resource": destination_arn
            }
        ]
    }

    try:
        # Put the destination policy
        logs_client.put_destination_policy(
            destinationName=destination_name,
            accessPolicy=json.dumps(policy_doc)
        )
        print(f"Destination policy set for {destination_name}")
    except logs_client.exceptions.ClientError as error:
        print(f"An error occurred: {error}")
        raise

def user_inputs():
    """
    This function will take user input for the Splunk-specific data points utilized by the
    Kinesis Data Firehose. These values will be provided by the Splunk team to be configured within
    AWS.
    """
    hec_token = input("Please enter the HEC Token:")
    endpoint_url = input("Please enter your endpoint URL:")
    return hec_token, endpoint_url

def parse_args():
    """
    Parse command-line arguments passed to the script.
    """
    parser = argparse.ArgumentParser(
        description='Deploy the Splunk/Kinesis Infrastructure to support logging for: CloudTrail'
        )
    parser.add_argument('-p', '--profile', required=True, type=str,
                        help='AWS profile name for SSO login')
    parser.add_argument('-r', '--region', required=True, type=str,
                        help='AWS region where the resources should be located')
    parser.add_argument('-a', '--account_id', required=True, type=str,
                        help='AWS account id of delegated administrator account')

    return parser.parse_args()


def main():
    """
    Main function of script
    """
    args = parse_args()

    names = {
        "bucket_name": f'splunk-cloudtrail-processor-bucket-{args.account_id}-{args.region}',
        "key_alias": f'alias/splunk-cloudtrail-processor-key-{args.account_id}-{args.region}',
        "function_name": f"splunk-cloudtrail-processor-function-{args.account_id}-{args.region}"
    }

    lambda_arn = f"arn:aws:lambda:{args.region}:{args.account_id}:function:{names['function_name']}"

    # Captures these values from user input
    hec_token, endpoint_url = user_inputs()

    # Establish session with specific profile and region from args
    session = boto3.Session(profile_name=args.profile, region_name=args.region)

    create_s3_bucket(session, names["bucket_name"], args.account_id, args.region)

    # Creates the KMS key & enables auto-rotation (if not enabled already, useful for subsequent
    # runs of the code)
    kms_key_arn = create_kms_key(session, names["key_alias"], args.region, args.account_id,)
    kms_key_id = kms_key_arn.split('/')[-1]  # The key ID is at the end of the ARN
    enable_rotation_if_not_set(session, kms_key_id)

    aws_params = {
    'session': session,
    'account_id': args.account_id,
    'region': args.region,
    'bucket_name': names["bucket_name"],
    }

    # Create custom role to be assigned to the firehose role below
    custom_policy_arn = create_firehose_policy(aws_params, names["key_alias"], lambda_arn)

    # Create the IAM role to be used
    role_arn = create_firehose_role(session, args.account_id, args.region, custom_policy_arn)

    # Create Lambda function
    create_lambda_function(session, names["function_name"], role_arn)

    # Create the Kinesis Data Firehose to send data to destination
    firehose_arn = create_firehose_stream(aws_params, endpoint_url, hec_token, lambda_arn, role_arn)

    create_encrypted_log_group_with_streams(session, args.region,
                                        kms_key_arn)
    create_cloudwatch_policy(aws_params)
    cloudwatch_role_arn = create_cloudwatch_role(session, args.account_id, args.region,
                                                 custom_policy_arn)

    destination_name = create_cloudwatch_logs_destination(session, args.account_id,
                                                          args.region, firehose_arn,
                                                          cloudwatch_role_arn)
    destination_arn = f"arn:aws:logs:{args.region}:{args.account_id}:destination:{destination_name}"

    put_destination_access_policy(session, args.account_id, args.region, destination_name)

    print("Successfully deployed the resources required to send CloudTrail logs to Splunk!")

    print("Please configure the sending CloudWatch Log Group Subscription Filter "
          f"with the following Destionation ARN: {destination_arn}.")

if __name__ == "__main__":
    main()
