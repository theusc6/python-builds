"""
This script sets up a system that automatically generates scheduled reports based on findings
from AWS Security Hub and sends them to an S3 bucket. 

The main components include creating an IAM role for executing the Lambda function,
creating a KMS key for encryption, setting up the Lambda function itself with the
necessary code and triggers, and finally, configuring a scheduler rule in AWS EventBridge
(or CloudWatch Events) to trigger the Lambda function according to the specified schedule.

The process involves various permissions and configurations, ensuring that the AWS Lambda
function has the necessary access to perform its tasks, such as reading findings, generating reports,
and writing them to an S3 bucket. It uses the KMS key to encrypt sensitive data, ensuring
security compliance.

If any step fails, the script provides feedback about what went wrong, helping with
troubleshooting. After successful setup, the system operates automatically,
providing regular security reports without further intervention.
"""

import argparse
import io
import time
import zipfile
import json
import boto3
from botocore.exceptions import ClientError

def create_function_role(session, account_id):
    """
    This function creates the role necessary for the script to function.
    """

    iam_client = session.client('iam')
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": [
                        "lambda.amazonaws.com",
                        "events.amazonaws.com",
                        "scheduler.amazonaws.com"

                    ]
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }
    role_name = 'role-XXX-securityhub-findings-report+prod-ops'
    securityhub_policy_arn="arn:aws:iam::aws:policy/AWSSecurityHubReadOnlyAccess"
    s3_policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
    lambda_basicexecutionrole = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    lambda_role = "arn:aws:iam::aws:policy/service-role/AWSLambdaRole"


    # Attempt to create the role
    try:
        iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description="Role for Lambda to email Inspector reports"
        )
        print(f"Successfully created role {role_name}")
    except iam_client.exceptions.EntityAlreadyExistsException:
        print(f"Role {role_name} already exists.")

    # Attempt to attach necessary policies to the role
    necessary_policies = {securityhub_policy_arn, s3_policy_arn, lambda_basicexecutionrole,
                          lambda_role}
    attached_policies_response = iam_client.list_attached_role_policies(RoleName=role_name)
    attached_policies = attached_policies_response['AttachedPolicies']
    attached_policy_arns = [policy['PolicyArn'] for policy in attached_policies]
    for policy_arn in necessary_policies:
        if policy_arn not in attached_policy_arns:
            iam_client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            print(f"Successfully attached policy {policy_arn} to role {role_name}")

    function_role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    return function_role_arn

def create_kms_key(session, key_alias, account_id, region, function_role_arn):
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
                        function_role_arn
                        ]
                },
                "Action": "kms:*",
                "Resource": "*"
            },
            {
                "Sid": "Allow Lambda to use the key",
                "Effect": "Allow",
                "Principal": {
                    "Service": "lambda.amazonaws.com"
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
                        "aws:SourceArn": (f"arn:aws:lambda:{region}:{account_id}:function:"
                        f"XXX-lambda-sechub-findings-report-{account_id}-{region}"
                        )
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
                Description='Key for security Hub findings report',
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
                Tags=[
                    {
                        'TagKey': 'Category',
                        'TagValue': 'Security'
                    }
                    ]
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

def create_lambda_function(session, function_name, handler_name, function_role_arn, region):
    """
    This function creates an AWS Lambda function.
    """
    lambda_client = session.client('lambda')

    # Specify the Lambda function code as a ZIP file
    function_code = (
        #Insert code here!!
        b"import boto3\n"
    )

    zip_stream = io.BytesIO()

    # Create a ZIP archive
    with zipfile.ZipFile(zip_stream, mode='w') as zipf:
        # Add the script as a file to the ZIP archive
        zipf.writestr('lambda_script.py', function_code)

    # Get the content of the ZIP archive as bytes
    zip_content = zip_stream.getvalue()

    try:
        response = lambda_client.create_function(
            FunctionName=function_name,
            Runtime='python3.11',
            Role=function_role_arn,
            Handler=handler_name,
            Code={
                'ZipFile': zip_content  # Provide the ZIP content here
            },
            Description='Generates latest AWS Security Hub report and sends to S3',
            Timeout=900, #This may need to be adjusted based on environment size
            MemorySize=1024, #This may need to be adjusted based on environment size
            Tags={
                'Category': 'Security'
            },
            Layers=[
                f'arn:aws:lambda:{region}:336392948345:layer:AWSSDKPandas-Python311:1'
            ]
        )
        print(f"Lambda function {function_name} created successfully.")
        return response['FunctionArn']  # Return the ARN of the created Lambda function

    except lambda_client.exceptions.ClientError as client_error:
        print(f"Error creating Lambda function: {client_error}")
        return None

def configure_scheduler_rule(session, config, lambda_arn):
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

    function_role_arn = config['function_role_arn']
    kms_key_arn = config['kms_key_arn']
    account_id = config['account_id']
    region = config['region']

    client = session.client('scheduler')

    schedule_name = f'XXX-sechub-eb-findings-report-{account_id}-{region}'

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
                'Arn': lambda_arn,
                'RetryPolicy': {
                    'MaximumEventAgeInSeconds': 86400,
                    'MaximumRetryAttempts': 185
                },
                'RoleArn': function_role_arn
            }
        )
        schedule_arn = f"arn:aws:events:{region}:{account_id}:rule/{schedule_name}"
        print(f'Schedule {schedule_name} has been created.')
        return schedule_arn


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
        return None

def assign_lambda_trigger(session, lambda_arn, schedule_arn, account_id):
    """
    Assigns the trigger to the lambda function created
    """
    lambda_client = session.client('lambda')

    try:
        lambda_client.add_permission(
            FunctionName=lambda_arn,
            StatementId='lambda-trigger-permission',
            Action='lambda:InvokeFunction',
            Principal='events.amazonaws.com',
            SourceArn=schedule_arn,
            SourceAccount=account_id,
        )
        print("Lambda trigger added successfully!")
        return True
    except lambda_client.exceptions.ClientError as error:
        print("Error adding permission:", error)
        return False


def parse_args():
    """
    Parse command-line arguments passed to the script.
    """
    parser = argparse.ArgumentParser(
        description='Deploy the security exporter service by
        providing the necessary arguments.'
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
    session = boto3.Session(profile_name=args.profile, region_name=args.region)

    function_role_arn = create_function_role(session, args.account_id)

    key_alias = f'alias/XXX-kms-sechub-findings-report-{args.account_id}-{args.region}'
    kms_key_arn = create_kms_key(session, key_alias, args.account_id,
                                 args.region, function_role_arn)

    function_name = f"XXX-lambda-sechub-findings-report-{args.account_id}-{args.region}"
    handler_name = 'lambda_script.main'


    lambda_arn = create_lambda_function(session, function_name, handler_name, function_role_arn,
                                        args.region)


    schedule_arn = configure_scheduler_rule(session, { # pylint: disable=unused-variable
    'function_role_arn': function_role_arn,
    'kms_key_arn': kms_key_arn,
    'account_id': args.account_id,
    'region': args.region
    }, lambda_arn)


    #assign_lambda_trigger(session, lambda_arn, schedule_arn, args.account_id)

if __name__ == "__main__":
    main()
