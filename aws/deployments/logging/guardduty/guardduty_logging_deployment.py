"""
Splunk Kinesis Integration for GuardDuty

This module deploys the necessary infrastructure for integrating AWS GuardDuty logs with Splunk
via Kinesis Data Streams and Kinesis Data Firehose. It covers the creation and configuration of
required AWS resources like S3 buckets, Kinesis streams, IAM roles, and policies.

Key Features:
- Creation of a dedicated S3 bucket for the Kinesis processor.
- Establishment of a KMS key for data encryption and its management.
- Setup of an IAM role and policy for the Firehose stream.
- Deployment of an EventBridge rule to capture GuardDuty findings.
- Configuration of the Kinesis Data Firehose to relay data to a specified Splunk endpoint.
- Integration of GuardDuty with the Kinesis stream via EventBridge.

Usage:
    Run the script and provide required command-line arguments:
    - AWS profile name for SSO login (`-p` or `--profile`)
    - AWS region where resources will be created (`-r` or `--region`)
    - AWS account ID for the delegated administrator account (`-a` or `--account_id`)
"""

import argparse
import time
import json
import boto3
from botocore.exceptions import ClientError

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
                Description='Key for Amazon Guard Duty & Splunk Logging',
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

def create_iam_policy(aws_params, key_alias):
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
                    f"/splunk-guardduty-processor-firehose-{account_id}-{region}"
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
                    f"/aws/kinesisfirehose/splunk/guardduty:log-stream:*"
                ]
            }
        ]
    }
    policy_name = f"policy-splunk-guardduty-processor-{account_id}-{region}"

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
    role_name = f'role-splunk-guardduty-processor-{account_id}-{region}'
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": [
                        "firehose.amazonaws.com",
                        "events.amazonaws.com"
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
    time.sleep(10)

    return role_arn

def create_guard_duty_eventbridge_rule(session, account_id, region):
    """
    This function creates the EventBridge rule that will be triggered 
    by new Guard Duty findings.
    """

    # Create an EventBridge client
    eventbridge = session.client('events')

    # Define the name of the rule
    guard_duty_rule_name = f'splunk-guardduty-rule-{account_id}-{region}'

    # Check if the rule already exists
    try:
        existing_rule = eventbridge.describe_rule(Name=guard_duty_rule_name)
        print(f"The rule {existing_rule['Arn']} already exists. Continuing processing.")
        return guard_duty_rule_name
    except eventbridge.exceptions.ResourceNotFoundException:
        print(f"The rule {guard_duty_rule_name} does not exist. Now creating...")

    # Define the event pattern for the rule
    event_pattern = {
        "source": ["aws.securityhub"],
        "detail-type": ["Security Hub Findings - Imported"],
        "detail": {
            "findings": {
            "ProductName": ["GuardDuty"]
            }
        }
    }

    try:
        # Create an EventBridge rule
        rule_response = eventbridge.put_rule(
            Name=guard_duty_rule_name,
            EventPattern=json.dumps(event_pattern),
            State='ENABLED',
            Description='CloudWatch Events with GuardDuty to set up automated finding alerts by '
            'sending GuardDuty finding events to a messaging hub to help increase the visibility '
            'of GuardDuty findings',
            Tags=[
                {
                    'Key': 'Category',
                    'Value': 'Security'
                },
            ],
        )

        print(f"Successfully created the Eventbrdige rule {rule_response['RuleArn']}.")

        return guard_duty_rule_name
    except boto3.exceptions.botocore.exceptions.BotoCoreError as client_error:
        # Handle specific errors here
        print(f"An error occurred while creating the rule: {client_error}")
        return None

def create_firehose_stream(aws_params, endpoint_url, hec_token, role_arn):
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
    log_group_name = aws_params['log_group_name']

    firehose_client = session.client('firehose')

    stream_name = f"splunk-guardduty-processor-firehose-{account_id}-{region}"

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
                        'LogGroupName': log_group_name,
                        'LogStreamName': 'BackupDelivery'
                    }
                },
                'ProcessingConfiguration': {
                    'Enabled': False,
                    'Processors': []
                },
                'CloudWatchLoggingOptions': {
                    'Enabled': True,
                    'LogGroupName': log_group_name,
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
        response = firehose_client.describe_delivery_stream(DeliveryStreamName=stream_name)
        firehose_arn = response['DeliveryStreamDescription']['DeliveryStreamARN']

        return firehose_arn

    except ClientError as client_error:
        print(f"An error occurred: {client_error}")
        return None


def add_target_to_guard_duty_eventbridge_rule(session, firehose_arn,
                                              role_arn, guard_duty_rule_name):
    """
    This function adds a target (Kinesis stream) to the previously created EventBridge Rule.

    :param session: Boto3 session.
    :param kinesis_stream_arn: The ARN of the Kinesis stream.
    :param guard_duty_rule_name: The name of the GuardDuty EventBridge rule.
    """

    # Create an EventBridge client
    eventbridge = session.client('events')

    # Configure the target as the Kinesis stream
    target_config = {
        "Id": "1",  # This is an identifier for the target in the rule
        "Arn": firehose_arn,
        "RoleArn": role_arn
        # event to the target
        # "RoleArn": "arn:aws:iam::<account>:role/<role-name>"
    }

    # Add the target to the rule
    try:
        response = eventbridge.put_targets(
            Rule=guard_duty_rule_name,
            Targets=[target_config]
        )

        # Check if targets are added successfully
        if response['FailedEntryCount'] > 0:
            print(f"Failed to add target(s) to {guard_duty_rule_name}.")
            return False

        print(f"Target(s) added successfully to {guard_duty_rule_name}.")
        return True

    except ClientError as client_error:
        print(f"An error occurred: {client_error}")
        return False

def user_inputs():
    """
    This function will take user input for the Splunk-specific data points utilized by the
    Kinesis Data Firehose. These values will be provided by the Splunk team to be configured within
    AWS.
    """
    hec_token = input("Please enter the HEC Token:")
    endpoint_url = input("Please enter your endpoint URL:")
    return hec_token, endpoint_url

def create_encrypted_log_group_with_streams(session, region, kms_key_arn, log_group_name):
    """
    Create an encrypted CloudWatch Log group with two log streams and a specified retention period.
    """
    logs_client = session.client('logs', region_name=region)
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

def parse_args():
    """
    Parse command-line arguments passed to the script.
    """
    parser = argparse.ArgumentParser(
        description='Deploy the Splunk/Kinesis Infrastructure to support logging for: Guard Duty'
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
        "bucket_name": f'splunk-guardduty-processor-bucket-{args.account_id}-{args.region}',
        "key_alias": f'alias/splunk-guardduty-processor-key-{args.account_id}-{args.region}',
        "log_group_name": '/aws/kinesisfirehose/splunk/guardduty'
    }

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
    'log_group_name': names["log_group_name"]
    }

    # Create custom role to be assigned to the firehose role below
    custom_policy_arn = create_iam_policy(aws_params, names["key_alias"])

    # Create the IAM role to be used
    role_arn = create_firehose_role(session, args.account_id, args.region, custom_policy_arn)

    # Create EventBridge rule triggered by GuardDuty findings
    guard_duty_rule_name = create_guard_duty_eventbridge_rule(session, args.account_id, args.region)

    # Create the Kinesis Data Firehose to send data to destination
    firehose_arn = create_firehose_stream(aws_params, endpoint_url, hec_token, role_arn)

    # Add the Kinesis stream as a target for the GuardDuty EventBridge rule
    add_target_to_guard_duty_eventbridge_rule(session, firehose_arn,
                                                        role_arn, guard_duty_rule_name)

    create_encrypted_log_group_with_streams(session, args.region,
                                            kms_key_arn, names["log_group_name"])

    print("Successfully deployed the resources required to send Guard Duty logs to Splunk!")

if __name__ == "__main__":
    main()
