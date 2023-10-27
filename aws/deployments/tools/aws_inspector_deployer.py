"""
This module provides functionality for enabling and configuring the Amazon Inspector service, 
including the creation of an Amazon S3 bucket and a KMS key for findings reports, along with 
all other dependencies and configurations.

The main components are:
    - Creation of a default role for AWS Systems Manager (SSM)
        -The default role for SSM will be created
        -"AWSSystemsManagerDefaultEC2InstanceManagementRole"
    - Enabling Default Host Management for SSM
        -Amazon Inspector will require SSM management of Ec2 instances for successful scanning
    - Assigning the above SSM default role to all Ec2 instances in the given region/account
    - Enabling Amazon Inspector V2
    - Creation of an IAM role for Amazon Inspector
    - Creation of a KMS key for findings report
    - Creation of an S3 bucket for findings report
    - Enabling key rotation for the KMS key if not already set
    - Configuring Scheduler Rule for regular assessments
    - Creation of an immediate report for initial assessment

The script accepts AWS profile name and region as command-line arguments.
The AWS profile should be the name of an AWS SSO profile, and it is a required argument. 
The region argument is optional, and if not provided, 'us-west-2'
will be used as the default region.

The orchestration of all these tasks is done in the main function. 

For more details about individual components, refer to the respective function's docstring.
"""
import argparse
import json
import time
import boto3

from botocore.exceptions import ClientError

def create_default_ssm_role(iam_client):
    """
    This function creates a role for AWS Systems Manager (SSM) with
    the default EC2 Instance Management policy attached and an instance profile associated with it. 

    The trust policy for the role allows EC2 instances to assume this role.
    This is required for EC2 instances to be managed by SSM.

    If the role or instance profile already exists, the function
    checks their settings and corrects any discrepancies.

    Parameters:
        iam_client (botocore.client.IAM): The IAM client object representing the IAM service.

    Returns:
        tuple: The name of the role and instance profile.
    """
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": [
                        "ec2.amazonaws.com",
                        "ssm.amazonaws.com"
                    ]
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }
    role_name = 'AWSSystemsManagerDefaultEC2InstanceManagementRole'
    ssmdefault_policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedEC2InstanceDefaultPolicy"
    cloudwatch_policy_arn="arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
    s3fullaccess_policy_arn="arn:aws:iam::aws:policy/AmazonS3FullAccess"
    ssmfullaccess_policy_arn="arn:aws:iam::aws:policy/AmazonSSMFullAccess"
    instance_profile_name = role_name

    # Attempt to create the role
    try:
        iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description="Role for default SSM host management"
        )
        print(f"Successfully created role {role_name}")
    except iam_client.exceptions.EntityAlreadyExistsException:
        print(f"Role {role_name} already exists.")

    # Attempt to attach necessary policies to the role
    necessary_policies = {ssmdefault_policy_arn, cloudwatch_policy_arn,
                          s3fullaccess_policy_arn, ssmfullaccess_policy_arn}
    attached_policies_response = iam_client.list_attached_role_policies(RoleName=role_name)
    attached_policies = attached_policies_response['AttachedPolicies']
    attached_policy_arns = [policy['PolicyArn'] for policy in attached_policies]
    for policy_arn in necessary_policies:
        if policy_arn not in attached_policy_arns:
            iam_client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            print(f"Successfully attached policy {policy_arn} to role {role_name}")

    # Attempt to create the instance profile
    try:
        iam_client.create_instance_profile(InstanceProfileName=instance_profile_name)
        print(f"Successfully created instance profile {instance_profile_name}")
    except iam_client.exceptions.EntityAlreadyExistsException:
        print(f"Instance profile {instance_profile_name} already exists.")

    # Attempt to add the role to the instance profile
    instance_profile_response = iam_client.get_instance_profile(
        InstanceProfileName=instance_profile_name
    )
    instance_profile_roles = [
        role['RoleName'] for role in
        instance_profile_response['InstanceProfile']['Roles']
    ]
    if role_name not in instance_profile_roles:
        iam_client.add_role_to_instance_profile(
            InstanceProfileName=instance_profile_name,
            RoleName=role_name
        )
        print(f"Successfully added role {role_name} to instance profile {instance_profile_name}")

    return role_name

def enable_default_host_management(ssm_client, role_name):
    """
    This function enables Default Host Management for the Systems Manager (SSM) service. 
    
    The function sets the default EC2 instance management role to the specified role name. 
    If an error occurs during the process, the error details are printed to the console.

    Parameters:
        ssm_client (botocore.client.SSM): The SSM client object representing the SSM service.
        role_name (str): The name of the role to be set as the default EC2 instance management role.

    """
    try:
        ssm_client.update_service_setting(
            SettingId='/ssm/managed-instance/default-ec2-instance-management-role',
            SettingValue=role_name
        )
        print('Successfully enabled Default Host Management for SSM!')
    except ClientError as client_error:
        print("Error enabling Default Host Management Configuration: ")
        print(f"Error enabling Default Host Management Configuration: "
            f"{client_error.response['Error']['Message']} | "
            f"Error Code: {client_error.response['Error']['Code']} | "
            f"Request ID: {client_error.response['ResponseMetadata']['RequestId']}")

def attach_role_to_instances(session, role_name, region):
    """
    Attach an IAM role to all EC2 instances in a specified region.

    Parameters:
        session (boto3.Session): The Boto3 session.
        role_name (str): The name of the IAM role.
        region (str): The region to search for instances.
    """
    ec2_client = session.client('ec2', region_name=region)
    iam_client = session.client('iam')

    # Get the instance profile
    instance_profile_response = iam_client.get_instance_profile(InstanceProfileName=role_name)
    instance_profile = instance_profile_response['InstanceProfile']

    # Get all instances in the region
    response = ec2_client.describe_instances()
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            # Attach the IAM role to the instance
            try:
                ec2_client.associate_iam_instance_profile(
                    IamInstanceProfile={
                        'Arn': instance_profile['Arn'],
                        'Name': instance_profile['InstanceProfileName']
                    },
                    InstanceId=instance_id
                )
                print(f"Successfully associated {role_name} with {instance_id}!")
            except ClientError as client_error:
                print(f"Failed to associate {role_name} with {instance_id}: {client_error}")


def enable_inspector_v2(session):
    """
    This function enables AWS Inspector v2 and all scan types.

    Parameters:
    session (boto3.Session): An AWS session object created by Boto3.

    Returns:
    None
    """
    inspector_client = session.client('inspector2')

    # Enable Amazon Inspector v2
    inspector_client.enable(
        resourceTypes=[
            'ECR','EC2','LAMBDA','LAMBDA_CODE',
        ]
    )

    print("Amazon Inspector v2 has been enabled for all resource types.")

def create_iam_role(session):
    """
    Creates an IAM role with specific policies and returns its ARN.

    Parameters:
    session (boto3.Session): An AWS session object created by Boto3.

    Returns:
    str: The ARN of the created IAM role.
    """
    iam_client = session.client('iam')

    role_name = 'role-XXX-awsinspector-findings-report+prod-ops'
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": [
                        "events.amazonaws.com",
                        "scheduler.amazonaws.com"
                    ]
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }

    try:
        create_role_response = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description='Role for AWS Inspector Findings Report',
            Tags=[
                {
                    'Key': 'Category',
                    'Value': 'Security'
                }
            ]
        )

        policy_arns = [
            'arn:aws:iam::aws:policy/AWSKeyManagementServicePowerUser',
            'arn:aws:iam::aws:policy/AmazonInspector2FullAccess',
        ]

        for policy_arn in policy_arns:
            iam_client.attach_role_policy(
                RoleName=role_name,
                PolicyArn=policy_arn
            )
        print(f"Creating {role_name}...")
        time.sleep(10)
        print(f"The role {role_name} successfully created.")
        return create_role_response['Role']['Arn']


    except ClientError as client_error:
        if client_error.response['Error']['Code'] == 'EntityAlreadyExists':
            print(f"The IAM role {role_name} already exists.")
            role_arn = iam_client.get_role(RoleName=role_name)['Role']['Arn']
            return role_arn

        print(f"An error occurred while creating the IAM role: "
            f"{client_error.response['Error']['Message']}")
        return None

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
                "Sid": "allow-inspector",
                "Effect": "Allow",
                "Principal": {
                    "Service": "inspector2.amazonaws.com"
                },
                "Action": [
                    "s3:PutObject",
                    "s3:PutObjectAcl",
                    "s3:AbortMultipartUpload"
                ],
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
                "Condition": {
                    "StringEquals": {
                        "aws:SourceAccount": account_id
                    },
                    "ArnLike": {
                        "aws:SourceArn": f"arn:aws:inspector2:{region}:{account_id}:report/*"
                    }
                }
            },
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
                'ID': 'XXX-securityhub-s3.13-default-lifecycle-policy',
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

    log_bucket_name= f"XXX-securityhub-s3.9accesslogging-{account_id}-{region}"

    try:
        s3_client.put_bucket_lifecycle_configuration(
            Bucket=bucket_name,
            LifecycleConfiguration=lifecycle_policy
        )
        print(f"Applied bucket lifecycle policy for bucket {bucket_name}.")
    except ClientError as client_error:
        print(f"An error occurred while applying lifecycle policy: "
              f"{client_error.response['Error']['Message']}")

    if 'XXX-securityhub-s3.9accesslogging' not in bucket_name:
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

def create_kms_key(session, key_alias, account_id, region, iam_role_arn):
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
                "Sid": "Enable IAM User Permissions",
                "Effect": "Allow",
                "Principal": {
                    "AWS": [
                        f"arn:aws:iam::{account_id}:root",
                        iam_role_arn
                        ]
                },
                "Action": "kms:*",
                "Resource": "*"
            },
            {
                "Sid": "Allow Amazon Inspector to use the key",
                "Effect": "Allow",
                "Principal": {
                    "Service": "inspector2.amazonaws.com"
                },
                "Action": [
                    "kms:Decrypt",
                    "kms:GenerateDataKey*"
                ],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "aws:SourceAccount": account_id
                    },
                    "ArnLike": {
                        "aws:SourceArn": f"arn:aws:inspector2:{region}:{account_id}:report/*"
                    }
                }
            }
        ]
    }

    retries = 0
    while retries < 3:
        try:
            response = kms_client.create_key(
                Policy=json.dumps(policy),
                Description='Key for Amazon Inspector findings report',
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

def configure_scheduler_rule(session, config):
    """
    This function configures a scheduler rule in AWS EventBridge. 
    It creates a new schedule with a specific schedule expression, flexible time window, and target.

    If a schedule with the same name already exists, a message is printed to the console.
    If an error occurs during the creation of the schedule, 
    the error message is printed to the console.

    Parameters:
    session (boto3.Session): An AWS session object created by Boto3.
    iam_role_arn (str): The ARN of the IAM role that EventBridge will assume when running tasks.
    bucket_name (str): The name of the S3 bucket where findings reports will be stored.
    kms_key_arn (str): The ARN of the KMS key that will be used to encrypt the findings reports.

    Returns:
    None
    """

    iam_role_arn = config['iam_role_arn']
    bucket_name = config['bucket_name']
    kms_key_arn = config['kms_key_arn']
    account_id = config['account_id']
    region = config['region']

    client = session.client('scheduler')

    input_json = f"""{{
        "ReportFormat": "CSV",
        "S3Destination": {{
            "BucketName": "{bucket_name}",
            "KmsKeyArn": "{kms_key_arn}"
        }}
    }}"""

    schedule_name = f'XXX-awsinspector-eb-findings-report-{account_id}-{region}'

    try:
        client.create_schedule(
            Name= schedule_name,
            KmsKeyArn= kms_key_arn,
            ScheduleExpression='cron(0 13 ? * MON *)',
            ScheduleExpressionTimezone='UTC',
            FlexibleTimeWindow={
                'Mode':'OFF'
            },
            State='ENABLED',
            Target={
                'Arn': 'arn:aws:scheduler:::aws-sdk:inspector2:createFindingsReport',
                'Input': input_json,
                'RetryPolicy': {
                    'MaximumEventAgeInSeconds': 86400,
                    'MaximumRetryAttempts': 185
                },
                'RoleArn': iam_role_arn
            }
        )

        print(f'Schedule {schedule_name} has been created.')

    except ClientError as client_error:
        error_message = client_error.response['Error']['Message']
        error_code = client_error.response['Error']['Code']

        if error_code == 'ConflictException':
            print(f'A ConflictException occurred. It seems the schedule already exists.'
                   f'Error Message: {error_message}')
        elif error_code == 'ValidationException':
            print(f'A ValidationException occurred. Please check your input parameters. '
                  f'Error Message: {error_message}')
        elif error_code == 'InternalServerException':
            print('An InternalServerException occurred. This might be a problem with AWS. '
                   f'Error Message: {error_message}')
        elif error_code == 'ResourceNotFoundException':
            print('A ResourceNotFoundException occurred. Some required resources might be missing. '
                   f'Error Message: {error_message}')
        elif error_code == 'ServiceQuotaExceededException':
            print(f'A ServiceQuotaExceededException occurred. You might have '
                  f'exceeded your service quota. '
                   f'Error Message: {error_message}')
        elif error_code == 'ThrottlingException':
            print(f'A ThrottlingException occurred. The request was throttled. '
                   f'Error Message: {error_message}')
        else:
            print(f'An unexpected error occurred: {client_error}')
            print(f'Error code: {error_code}')

def create_immediate_report(inspector_client, bucket_name, kms_key_arn):
    """Creates an immediate report."""

    # Prepare the input JSON
    response = inspector_client.create_findings_report(
            reportFormat='CSV',
            s3Destination={
                "bucketName": bucket_name,
                "kmsKeyArn": kms_key_arn
            }
    )

    # Get the report ID
    report_id = response['reportId']

    # Wait for the report to be created
    while True:
        response = inspector_client.get_findings_report_status(reportId=report_id)
        if response['status'] == 'SUCCEEDED':
            break
        time.sleep(10)  # Wait for 10 seconds before checking again

    # Report has been created
    print('Report has been created!')

def main():
    """
    This is the main function that orchestrates the enabling of Amazon Inspector, 
    creation of an S3 bucket, and creation of a KMS key. 

    AWS profile name and region are input parameters, 
    with 'us-west-2' set as the default region if no region is provided.

    Parameters are provided through the command line using argparse.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-p','--profile', required=True,
                        help='The name of the AWS SSO profile to use')
    parser.add_argument('-r','--region', default='us-west-2', help='The AWS region to use')

    args = parser.parse_args()


    session = boto3.Session(profile_name=args.profile)
    account_id = session.client('sts').get_caller_identity().get('Account')
    inspector_client = session.client('inspector2')
    ssm_client = session.client('ssm')


    iam_client=session.client('iam')
    role_name = create_default_ssm_role(iam_client)
    enable_default_host_management(ssm_client, role_name)
    attach_role_to_instances(session, role_name, args.region)
    enable_inspector_v2(session)

    iam_role_arn = create_iam_role(session)

    key_alias = f'alias/XXX-awsinspector-kms-findings-report-{account_id}-{args.region}'
    kms_key_arn = create_kms_key(session, key_alias, account_id, args.region, iam_role_arn)

    bucket_name = f'XXX-awsinspector-s3-findings-report-{account_id}-{args.region}'
    create_s3_bucket(session, bucket_name, account_id, args.region)

    key_alias = f'alias/XXX-awsinspector-kms-findings-report-{account_id}-{args.region}'
    kms_key_arn = create_kms_key(session, key_alias, account_id, args.region, iam_role_arn)
    kms_key_id = kms_key_arn.split('/')[-1]  # The key ID is at the end of the ARN
    enable_rotation_if_not_set(session, kms_key_id)

    configure_scheduler_rule(session, {
    'iam_role_arn': iam_role_arn,
    'bucket_name': bucket_name,
    'kms_key_arn': kms_key_arn,
    'account_id': account_id,
    'region': args.region
    })

    create_immediate_report(inspector_client, bucket_name, kms_key_arn)

    print('AWS Inspector has now been enabled and configured!')

if __name__ == '__main__':
    main()
