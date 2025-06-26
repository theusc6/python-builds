"""
This script deploys infrastructure to support logging for AWS CloudTrail using Splunk and Kinesis. 
It allows for creating CloudWatch Log Groups and setting up Kinesis Firehose Subscription Filters 
to forward logs to Splunk. 

The script uses boto3 to interact with AWS services and manages resources such as CloudWatch 
Log Groups and Kinesis Firehose. It gathers user input for necessary configuration details and 
executes the necessary steps to set up the logging infrastructure.

!This script must be ran last in a two-part series! 

A separate script, "kinesis_cloudtrail_deployment.py" must first be ran in the target account
to prepare the infrastructure configured for the subscription filter. This script is used for
cross-account delivery of cloudwatch logs.

Usage:
  The script is executed from the command line and requires three arguments:
  - AWS profile name for SSO login
  - AWS region where resources will be located
  - AWS account ID of the delegated administrator account

Example:
  python3 this_script.py -p your_profile -r us-west-2 -a 123456789012
"""

import argparse
import boto3
from botocore.exceptions import ClientError


def parse_args():
    """
    Parse command-line arguments passed to the script.
    """
    parser = argparse.ArgumentParser(
        description='Deploy the Splunk/Kinesis Infrastructure to support logging for CloudTrail.'
    )
    parser.add_argument('-p', '--profile', required=True, type=str,
                        help='AWS profile name for SSO login.')
    parser.add_argument('-r', '--region', required=True, type=str,
                        help='AWS region where the resources should be located.')
    parser.add_argument('-a', '--account_id', required=True, type=str,
                        help='AWS account id of delegated administrator account.')

    return parser.parse_args()

def get_user_input():
    """
    Gather user input for CloudWatch log group name, Kinesis Firehose ARN,
    log format, and subscription filter name.
    """
    default_log_format = ""
    log_group_name = input("Enter the CloudWatch Log Group name: ")
    destination_arn = str(input("Enter the Kinesis Firehose Destination ARN: "))
    log_format = input(f"Enter the log format [{default_log_format}]: ") or default_log_format
    filter_name = input("Enter the filter name: ")

    return log_group_name, destination_arn, log_format, filter_name

def create_log_group(session, log_group_name):
    """
    Ensure the CloudWatch Log Group exists, create if it does not.
    """
    logs_client = session.client('logs')

    try:
        logs_client.create_log_group(logGroupName=log_group_name)
        print(f"Log group {log_group_name} created.")
    except logs_client.exceptions.ResourceAlreadyExistsException:
        print(f"Log group {log_group_name} already exists. Continuing with configuration.")

def setup_subscription_filter(session, log_group_name, filter_name, log_format, destination_arn ):
    """
    Create or update the subscription filter for the log group.
    """
    logs_client = session.client('logs')
    try:
        print(destination_arn)
        logs_client.put_subscription_filter(
            logGroupName=log_group_name,
            filterName=filter_name,
            filterPattern=log_format,
            destinationArn=destination_arn
        )
        print(f"Subscription filter for {log_group_name} created/updated.")
    except ClientError as client_error:
        print(f"Error creating/updating subscription filter: {client_error}")

def main():
    """
    Main function orchestrating the script execution.
    """

    args = parse_args()

    # Establish session with specific profile and region from args
    session = boto3.Session(profile_name=args.profile, region_name=args.region)

    log_group_name, destination_arn, log_format, filter_name = get_user_input()


    create_log_group(session, log_group_name)
    setup_subscription_filter(session, log_group_name, filter_name, log_format, destination_arn)

if __name__ == "__main__":
    main()
