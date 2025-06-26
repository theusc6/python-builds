#!/usr/bin/env python3
"""
VPC Flow Logs Sender Script
Sets up IAM roles and configures VPC Flow Logs to send to Security Tooling account
"""

import argparse
import time
import json
import sys

import boto3
from botocore.exceptions import ClientError

# Security Tooling Account (hardcoded destination)
SECURITY_TOOLING_ACCOUNT = '*'


def get_aws_clients(region, profile):
    """Initialize AWS clients for the specified region and profile"""
    try:
        # Create session with specific profile
        session = boto3.Session(profile_name=profile, region_name=region)

        sts_client = session.client('sts')
        iam_client = session.client('iam')
        ec2_client = session.client('ec2')

        # Get current account ID
        account_id = sts_client.get_caller_identity()['Account']

        return sts_client, iam_client, ec2_client, account_id
    except ClientError as error:
        print(f"Error initializing AWS clients: {error}")
        sys.exit(1)


def create_iam_policy(iam_client, sender_account, region):
    """Create customer managed IAM policy for flow logs"""
    policy_name = f'policy-splunk-flowlogs-sender-{sender_account}'

    # Policy document
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": (
                    f"arn:aws:iam::{sender_account}:role/"
                    f"role-splunk-flowlogs-sender-{sender_account}"
                ),
                "Condition": {
                    "StringEquals": {
                        "iam:PassedToService": "delivery.logs.amazonaws.com"
                    },
                    "StringLike": {
                        "iam:AssociatedResourceARN": [
                            f"arn:aws:ec2:{region}:{sender_account}:vpc/*"
                        ]
                    }
                }
            },
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogDelivery",
                    "logs:DeleteLogDelivery",
                    "logs:ListLogDeliveries",
                    "logs:GetLogDelivery"
                ],
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": (
                    f"arn:aws:iam::{SECURITY_TOOLING_ACCOUNT}:role/"
                    f"AWSLogDeliveryFirehoseCrossAccountRole-{SECURITY_TOOLING_ACCOUNT}"
                )
            }
        ]
    }

    try:
        # Try to create the policy
        response = iam_client.create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy_document),
            Description="Policy for sending VPC Flow Logs to Security Tooling account",
            Tags=[
                {
                    'Key': 'Category',
                    'Value': 'Security'
                }
            ]
        )
        policy_arn = response['Policy']['Arn']
        print(f"Successfully created IAM policy: {policy_name}")
        return True, policy_arn

    except ClientError as error:
        if error.response['Error']['Code'] == 'EntityAlreadyExists':
            # Policy already exists, get its ARN
            policy_arn = f"arn:aws:iam::{sender_account}:policy/{policy_name}"
            print(f"IAM policy {policy_name} already exists")

            # Check if the policy document needs updating
            try:
                # Get current policy document
                current_policy = iam_client.get_policy(PolicyArn=policy_arn)
                current_version_id = current_policy['Policy']['DefaultVersionId']

                current_policy_version = iam_client.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=current_version_id
                )

                current_document = current_policy_version['PolicyVersion']['Document']
                new_document = policy_document

                # Compare policy documents (normalize for comparison)
                if json.dumps(current_document, sort_keys=True) != json.dumps(new_document, sort_keys=True):
                    print(f"Policy content has changed, updating {policy_name}")

                    # Create new policy version
                    iam_client.create_policy_version(
                        PolicyArn=policy_arn,
                        PolicyDocument=json.dumps(policy_document),
                        SetAsDefault=True
                    )
                    print(f"Updated IAM policy {policy_name} with new version")

                    # Delete old version if it's not v1
                    if current_version_id != 'v1':
                        try:
                            iam_client.delete_policy_version(
                                PolicyArn=policy_arn,
                                VersionId=current_version_id
                            )
                        except ClientError:
                            pass  # Ignore errors when deleting old versions
                else:
                    print(f"Policy content unchanged, skipping update for {policy_name}")

            except ClientError as update_error:
                print(f"Warning: Could not check/update policy: {update_error}")

            return True, policy_arn

        print(f"Error creating IAM policy: {error}")
        return False, None


def create_iam_role(iam_client, sender_account, policy_arn):
    """Create IAM role and attach customer managed policy"""
    role_name = f'role-splunk-flowlogs-sender-{sender_account}'

    # Trust policy for the role
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "delivery.logs.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }

    try:
        # Check if role exists
        try:
            iam_client.get_role(RoleName=role_name)
            print(f"IAM role {role_name} already exists")
        except ClientError as error:
            if error.response['Error']['Code'] == 'NoSuchEntity':
                # Create the role
                print(f"Creating IAM role: {role_name}")
                iam_client.create_role(
                    RoleName=role_name,
                    AssumeRolePolicyDocument=json.dumps(trust_policy),
                    Description="Role for sending VPC Flow Logs to Security Tooling account",
                    Tags=[
                        {
                            'Key': 'Category',
                            'Value': 'Security'
                        }
                    ]
                )
                print(f"Successfully created IAM role: {role_name}")
                time.sleep(10)
            else:
                raise

        # Attach the customer managed policy to the role
        try:
            iam_client.attach_role_policy(
                RoleName=role_name,
                PolicyArn=policy_arn
            )
            print(f"Successfully attached policy to role: {role_name}")
            time.sleep(10)
        except ClientError as error:
            if error.response['Error']['Code'] != 'EntityAlreadyExists':
                print(f"Error attaching policy to role: {error}")
                return False, None

    except ClientError as error:
        print(f"Error creating IAM role: {error}")
        return False, None

    return True, role_name


def get_vpcs(ec2_client, region, vpc_id=None):
    """Get VPCs - either all VPCs or a specific one"""
    try:
        if vpc_id:
            # Get specific VPC
            response = ec2_client.describe_vpcs(VpcIds=[vpc_id])
            vpcs = response['Vpcs']
            print(f"Found VPC {vpc_id} in region {region}")
        else:
            # Get all VPCs
            response = ec2_client.describe_vpcs()
            vpcs = response['Vpcs']
            print(f"Found {len(vpcs)} VPCs in region {region}")

        return vpcs
    except ClientError as error:
        print(f"Error getting VPCs: {error}")
        return []


def create_flow_log(ec2_client, vpc_id, sender_account, region, role_name):
    # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-locals
    """Create flow log for a specific VPC"""
    flow_log_name = f"securityhub-ec2.6flowlog-{sender_account}-{region}-{vpc_id}"
    role_arn = f"arn:aws:iam::{sender_account}:role/{role_name}"
    destination_firehose = f'splunk-flowlog-processor-firehose-{SECURITY_TOOLING_ACCOUNT}-{region}'
    destination_arn = (
        f"arn:aws:firehose:{region}:{SECURITY_TOOLING_ACCOUNT}:"
        f"deliverystream/{destination_firehose}"
    )

    try:
        # Check if flow log already exists for this VPC
        existing_flow_logs = ec2_client.describe_flow_logs(
            Filters=[
                {
                    'Name': 'resource-id',
                    'Values': [vpc_id]
                }
            ]
        )

        # Check if there's already a flow log with the same kinesis-firehose destination
        for flow_log in existing_flow_logs['FlowLogs']:
            if (flow_log['LogDestinationType'] == 'kinesis-data-firehose' and
                flow_log['LogDestination'] == destination_arn):
                print(f"Flow log already exists for VPC {vpc_id} "
                      f"with same kinesis-firehose destination")
                return True

        print(f"Creating flow log for VPC: {vpc_id}")
        log_format = ('${account-id} ${interface-id} ${srcaddr} ${dstaddr} '
                     '${srcport} ${dstport} ${protocol} ${packets} ${bytes} '
                     '${start} ${end} ${action} ${log-status}')

        # Always use cross-account delivery since Firehose is in Security Tooling account
        print(f"Cross-account delivery (sender: {sender_account} → security tooling: {SECURITY_TOOLING_ACCOUNT})")
        response = ec2_client.create_flow_logs(
            ResourceIds=[vpc_id],
            ResourceType='VPC',
            TrafficType='ALL',
            LogDestinationType='kinesis-data-firehose',
            LogDestination=destination_arn,
            DeliverLogsPermissionArn=role_arn,
            DeliverCrossAccountRole=f"arn:aws:iam::{SECURITY_TOOLING_ACCOUNT}:role/AWSLogDeliveryFirehoseCrossAccountRole-{SECURITY_TOOLING_ACCOUNT}",
            MaxAggregationInterval=600,  # 10 minutes
            LogFormat=log_format,
            TagSpecifications=[
                {
                    'ResourceType': 'vpc-flow-log',
                    'Tags': [
                        {
                            'Key': 'Name',
                            'Value': flow_log_name
                        },
                        {
                            'Key': 'Category',
                            'Value': 'Security'
                        }
                    ]
                }
            ]
        )

        if response['Unsuccessful']:
            print(f"Failed to create flow log for VPC {vpc_id}: {response['Unsuccessful']}")
            return False

        flow_log_id = response['FlowLogIds'][0]
        print(f"Successfully created flow log {flow_log_id} for VPC {vpc_id}")
        return True

    except ClientError as error:
        print(f"Error creating flow log for VPC {vpc_id}: {error}")
        return False


def setup_vpc_flow_logs(region, sender_account, profile, vpc_id=None, dry_run=False):
    # pylint: disable=too-many-locals
    """Main function to set up VPC flow logs"""
    print(f"Starting VPC Flow Logs setup in region {region}")
    print(f"Using AWS profile: {profile}")
    print(f"Sender account: {sender_account}")
    print(f"Target Security Tooling account: {SECURITY_TOOLING_ACCOUNT}")
    if vpc_id:
        print(f"Target: VPC {vpc_id}")
    else:
        print("Target: All VPCs in the region")

    if dry_run:
        print("DRY RUN MODE - No changes will be made")
        return True

    # Initialize AWS clients
    _, iam_client, ec2_client, current_account_id = get_aws_clients(region, profile)

    # Verify we're in the correct sender account
    if current_account_id != sender_account:
        print(f"ERROR: You're authenticated to account {current_account_id} "
              f"but specified sender account {sender_account}")
        print("Please use the correct AWS profile or specify the correct sender account")
        return False

    # Step 1: Create IAM policy
    policy_success, policy_arn = create_iam_policy(
        iam_client, sender_account, region
    )
    if not policy_success:
        print("Failed to create IAM policy")
        return False

    # Step 2: Create IAM role and attach policy
    role_success, role_name = create_iam_role(iam_client, sender_account, policy_arn)
    if not role_success:
        print("Failed to create IAM role")
        return False

    # Step 3: Get VPCs
    vpcs = get_vpcs(ec2_client, region, vpc_id)
    if not vpcs:
        print("No VPCs found or error retrieving VPCs")
        return False

    # Step 4: Setup flow logs for VPCs
    success_count = 0
    for vpc in vpcs:
        current_vpc_id = vpc['VpcId']
        if create_flow_log(ec2_client, current_vpc_id, sender_account,
                          region, role_name):
            success_count += 1

    print(f"Successfully configured flow logs for {success_count}/{len(vpcs)} VPCs")

    if success_count == len(vpcs):
        print("VPC Flow Logs setup completed successfully!")
        return True

    print("VPC Flow Logs setup completed with some failures")
    return False


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Setup VPC Flow Logs sender configuration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Setup flow logs for all VPCs in sender account *
  python flowlogs_sender.py -p myprofile -r us-west-2 -s *

  # Setup flow logs for a specific VPC in sender account
  python flowlogs_sender.py -p prod-profile -r us-east-1 \\
    -s * -v vpc-1234567890abcdef0

  # Dry run to see what would be done
  python flowlogs_sender.py -p dev-profile -r us-west-2 \\
    -s * --dry-run

Note: All flow logs are sent to the Security Tooling account (*)
        """
    )

    parser.add_argument('-p', '--profile', required=True,
                       help='AWS profile name for authentication')
    parser.add_argument('-r', '--region', required=True,
                       help='AWS region (e.g., us-west-2, us-east-1)')
    parser.add_argument('-s', '--sender-account', required=True,
                       help='Sender account ID (account where VPCs exist and script is deployed)')
    parser.add_argument('-v', '--vpc-id',
                       help='Specific VPC ID to configure '
                            '(if not provided, all VPCs will be configured)')
    parser.add_argument('--dry-run', action='store_true',
                       help='Show what would be done without making changes')

    args = parser.parse_args()

    try:
        success = setup_vpc_flow_logs(args.region, args.sender_account, args.profile,
                                     args.vpc_id, args.dry_run)
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except (ClientError, OSError, ValueError) as error:
        print(f"Unexpected error: {error}")
        sys.exit(1)


if __name__ == '__main__':
    main()
