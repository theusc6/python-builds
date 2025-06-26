"""
This module is used for preparing the AWS environment for Terraform deployments,
including creating necessary S3 buckets, IAM roles, and DynamoDB tables.
"""

import argparse
import time
import json
import boto3
from botocore.exceptions import ClientError

def create_github_actions_role(session, account_id, region):
    """
    This function creates an IAM role with a trust policy specifically designed
    for GitHub Actions to assume this role. It attaches the 'AdministratorAccess'
    policy to the role to provide comprehensive permissions for managing AWS resources.
    """
    iam_client = session.client('iam')
    role_name = f'role-terraform_github_actions-{account_id}-{region}'
    trust_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": ["arn:aws:iam::*:role/Terraform_github_actions"]
                },
                "Action": "sts:AssumeRole"
            }
        ]
    })
    try:
        iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=trust_policy,
            Description="Role for GitHub Actions to deploy Terraform configurations."
        )
        print(f"Role {role_name} created successfully.")
    except ClientError as error:
        print(f"Failed to create role: {error.response['Error']['Message']}")
        return

    # Attach AdministratorAccess policy to the role
    policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    try:
        iam_client.attach_role_policy(
            RoleName=role_name,
            PolicyArn=policy_arn
        )
        print(f"Attached AdministratorAccess policy to {role_name}.")
    except ClientError as error:
        print(f"Failed to attach policy: {error.response['Error']['Message']}")


def create_s3_bucket(session, bucket_name, account_id, region):
    """
    This function creates an Amazon S3 bucket with a specified name, policy, tagging,
    versioning configuration, public access block configuration, and lifecycle policy.
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
                    'DaysAfterInitiation': 7
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

def create_dynamodb_table_for_tf_lock(session, table_name, region):
    """
    This function creates a DynamoDB table with provisioned throughput and
    auto-scaling for Terraform state locking, and enables point-in-time recovery.
    """
    dynamodb_client = session.client('dynamodb', region_name=region)
    application_autoscaling_client = session.client('application-autoscaling', region_name=region)

    table_params = {
        'TableName': table_name,
        'AttributeDefinitions': [
            {
                'AttributeName': 'LockID',
                'AttributeType': 'S'
            }
        ],
        'KeySchema': [
            {
                'AttributeName': 'LockID',
                'KeyType': 'HASH'
            }
        ],
        'BillingMode': 'PROVISIONED',
        'ProvisionedThroughput': {
            'ReadCapacityUnits': 1,
            'WriteCapacityUnits': 1
        },
        'DeletionProtectionEnabled':True
    }

    # Create the DynamoDB table
    try:
        dynamodb_client.create_table(**table_params)
        print(f"DynamoDB table {table_name} created successfully.")
    except ClientError as client_error:
        if client_error.response['Error']['Code'] == 'ResourceInUseException':
            print(f"The table {table_name} already exists.")
        else:
            print(f"An error occurred: {client_error.response['Error']['Message']}")
    time.sleep(15)
    # Enable point-in-time recovery
    try:
        dynamodb_client.update_continuous_backups(
            TableName=table_name,
            PointInTimeRecoverySpecification={
                'PointInTimeRecoveryEnabled': True
            }
        )
        print(f"Point-in-time recovery enabled for table {table_name}.")
    except ClientError as client_error:
        print(f"An error occurred enabling point-in-time "
              f"recovery: {client_error.response['Error']['Message']}")

# Configure Auto Scaling for read and write capacity
    resource_id = f'table/{table_name}'
    service_namespace = 'dynamodb'

    for dimension in ['ReadCapacityUnits', 'WriteCapacityUnits']:
        scalable_dimension = f'dynamodb:table:{dimension}'
        try:
            application_autoscaling_client.register_scalable_target(
                ServiceNamespace=service_namespace,
                ResourceId=resource_id,
                ScalableDimension=scalable_dimension,
                MinCapacity=1,
                MaxCapacity=10
            )
            print(f"Auto-scaling registered for {dimension}.")
        except ClientError as client_error:
            print(f"An error occurred registering auto-scaling: "
                  f"{client_error.response['Error']['Message']}")

        # Create scaling policy for the scalable target
        try:
            application_autoscaling_client.put_scaling_policy(
                PolicyName=f'{table_name}-{dimension}-ScalingPolicy',
                ServiceNamespace=service_namespace,
                ResourceId=resource_id,
                ScalableDimension=scalable_dimension,
                PolicyType='TargetTrackingScaling',
                TargetTrackingScalingPolicyConfiguration={
                    'TargetValue': 70.0,
                    'PredefinedMetricSpecification': {
                        'PredefinedMetricType': 'DynamoDBReadCapacityUtilization' if 
                        dimension == 'ReadCapacityUnits' else 'DynamoDBWriteCapacityUtilization'
                    },
                    'ScaleInCooldown': 60,
                    'ScaleOutCooldown': 60
                }
            )
            print(f"Auto-scaling policy created for {dimension}.")
        except ClientError as client_error:
            print(f"An error occurred creating scaling policy: "
                  f"{client_error.response['Error']['Message']}")
def main():
    """
    Main function to orchestrate the setup of AWS resources for Terraform deployments.
    """

    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--profile', required=False,
                        help='The name of the AWS SSO profile to use')
    parser.add_argument('-r', '--region', default='us-west-2', help='The AWS region to use')
    parser.add_argument('-a', '--account_id', required=False,
                        help='Please provide the account ID of the target AWS Account')
    parser.add_argument('-n', '--project_name', required=True,
                        help='The name of the related project')
    parser.add_argument('--create_s3', action='store_true',
                        help='Create S3 bucket for Terraform state')
    parser.add_argument('--create_role', action='store_true', help='Create GitHub Actions role')
    parser.add_argument('--create_dynamodb', action='store_true',
                        help='Create DynamoDB table for Terraform state locking')
    args = parser.parse_args()
    session = boto3.Session(profile_name=args.profile)

    if args.create_s3:
        # Create S3 bucket for Terraform state
        bucket_name = f'terraform-state-{args.project_name}-{args.account_id}-{args.region}'
        create_s3_bucket(session, bucket_name, args.account_id, args.region)

    if args.create_role:
        # Create GitHub Actions role
        create_github_actions_role(session, args.account_id, args.region)

    if args.create_dynamodb:
        # Create DynamoDB table for Terraform state locking
        table_name = f'terraform-lock-{args.project_name}-{args.account_id}-{args.region}'
        create_dynamodb_table_for_tf_lock(session, table_name, args.region)

    print("Account prep is now complete!")

if __name__ == '__main__':
    main()
