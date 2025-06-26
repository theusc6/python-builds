"""
Find AWS Workspaces Across Multiple AWS Accounts

This script is used to find AWS WorkSpaces across multiple AWS accounts associated with
an AWS organization. 

It operates by first retrieving a list of all the AWS accounts in the organization. 
It then assumes a role in each of these accounts, giving it the permissions needed to find 
the AWS WorkSpaces in the account.

The information about each workspace found is stored in a pandas DataFrame. Once all 
accounts have been searched, the DataFrame is saved to an Excel file. A summary table, 
listing the number of WorkSpaces found in each account, is also added to the Excel file.

This script is meant to be run from the command line and requires the following 
arguments:

--master_account_id: The AWS account ID of the master account in the organization.
--master_account_name: The name of the master account in the organization.
--profile_name: The AWS CLI profile to use for authenticating with AWS.

The script uses the Boto3 AWS SDK for Python and requires the following Python packages: 
boto3, argparse, pandas.
"""

import argparse
import boto3
import pandas as pd
from botocore.exceptions import BotoCoreError, ClientError


def find_workspaces(aws_region, session, account_id, account_name):
    """
    Finds and prints AWS WorkSpaces in a given AWS account and region.

    This function uses the 'describe_workspaces' method of the AWS WorkSpaces service 
    to fetch information about each workspace in the account. It prints out the 
    Workspace ID, Directory ID, User Name, State, and Region for each workspace. 
    The information is also compiled into a list of dictionaries which is returned 
    by the function.

    Args:
        region (str): The region in which to find the WorkSpaces.
        session (boto3.Session): The Boto3 session object for the account.
        account_id (str): The AWS account ID.
        account_name (str): The name of the AWS account.

    Returns:
        list: A list of dictionaries, each containing information about a workspace. 
        Each dictionary contains the following keys: 'Account ID', 'Account Name', 
        'Workspace ID', 'Directory ID', 'User Name', 'State', and 'Region'.
    """
    workspace = session.client('workspaces', region_name=region)
    paginator = workspace.get_paginator('describe_workspaces')

    data = []
    for page in paginator.paginate():
        for workspace in page['Workspaces']:
            workspace_id = workspace['WorkspaceId']
            directory_id = workspace['DirectoryId']
            user_name = workspace['UserName']
            workspace_state = workspace['State']
            print(f'Found Workspace - Workspace ID: {workspace_id}, '
                  f'Directory ID: {directory_id}, '
                  f'User Name: {user_name}, '
                  f'State: {workspace_state}, '
                  f'Region: {aws_region}')

            data.append({
                'Account ID': account_id,
                'Account Name': account_name,
                'Workspace ID': workspace_id,
                'Directory ID': directory_id,
                'User Name': user_name,
                'State': workspace_state,
                'Region': aws_region
            })

    return data

def get_organization_accounts(master_sess):
    """
    Retrieves a list of all the accounts associated with an
    AWS organization using a given AWS session.

    This function uses the 'organizations' service client
    of the given boto3 session to interact with AWS Organizations.
    It retrieves all accounts under the organization linked
    with the master session provided. It uses pagination to handle
    large number of accounts. 

    The function prints each account's ID and Name, and returns a list of all accounts.

    Parameters:
    master_sess (boto3.Session): A session representing the
    AWS credentials of the master account in the organization.

    Returns:
    list[dict]: A list of dictionaries, with each dictionary representing
    an AWS account in the organization.
    Each dictionary contains account attributes such
    as 'Id', 'Name', 'Arn', 'Email', 'JoinedMethod', etc.
    """
    organizations = master_sess.client('organizations')
    paginator = organizations.get_paginator('list_accounts')
    accounts_list = []

    for page in paginator.paginate():
        accounts_list.extend(page['Accounts'])

    for account_item in accounts_list:
        print(f'Account ID: {account_item["Id"]}, Name: {account_item["Name"]}')

    return accounts_list


def assume_role_in_account(account_id, role_name, master_sess):
    """
    Assumes a role in a specified AWS account and creates a
    new session with the assumed role's credentials.

    This function uses the AWS Security Token Service (STS) to
    assume a role in a specified AWS account.
    It then creates a new boto3 session using the credentials of the assumed role.

    Parameters:
    account_id (str): The ID of the AWS account in which to assume the role.
    role_name (str): The name of the role to assume in the specified account.
    master_session (boto3.Session): A session representing the AWS credentials
    of the master account.

    Returns:
    boto3.Session: A new session object representing the AWS credentials of the assumed role.
    """
    print(f'\nAssuming role in account {account_id}: arn:aws:iam::{account_id}:role/{role_name}')
    sts = master_sess.client('sts')
    response = sts.assume_role(
        RoleArn=f'arn:aws:iam::{account_id}:role/{role_name}',
        RoleSessionName='WorkspaceFinder'
    )

    return boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken']
    )

def parse_arguments():
    """
    Parse command line arguments.
    """
    parser = argparse.ArgumentParser(
        description="Script to generate AWS IAM report."
    )

    parser.add_argument(
        "--master_account_id",
        default="*",
        help="AWS Master account id. Default: *"
    )

    parser.add_argument(
        "--master_account_name",
        default="master",
        help="AWS Master account name. Default: master"
    )

    parser.add_argument(
        "--profile_name",
        required=True,
        default="n/a",
        help="AWS profile name. Default: default"
    )

    return parser.parse_args()


if __name__ == '__main__':
    args = parse_arguments()

    PROFILE_NAME = args.profile_name
    master_session = boto3.Session(profile_name=args.profile_name)
    regions = ["us-west-1",
               "us-west-2", 
               "us-east-1", 
               "us-east-2", 
               "ap-southeast-1",
               "me-south-1", 
               "me-central-1", 
               "ap-east-1"]
    accounts = get_organization_accounts(master_session)
    print(f'Found {len(accounts)} accounts in the organization.')
    CROSS_ACCOUNT_ROLE_NAME = 'OrganizationAccountAccessRole'

    # Add master account to the list of accounts and remove excluded accounts
        # Add master account to the list of accounts
    MASTER_ACCOUNT_ID = args.master_account_id
    MASTER_ACCOUNT_NAME = args.master_account_name
    MASTER_ACCOUNT = {'Id': MASTER_ACCOUNT_ID, 'Name': MASTER_ACCOUNT_NAME}

    # Add excluded account IDs - these are excluded due to 'suspended' status.
    # accounts will be deleted in 90 days from suspension date
    excluded_account_ids = []

    # Remove the master account and excluded accounts from the list
    accounts = [account
                 for account in accounts
                 if account['Id'] != MASTER_ACCOUNT_ID
                 and account['Id'] not in excluded_account_ids
                 ]
    accounts.append(MASTER_ACCOUNT)

    # Iterate through the accounts, assume role, and find WorkSpaces in all regions
    output_data = []
    for acct in accounts:
        try:
            if acct['Id'] == MASTER_ACCOUNT_ID:
                account_session = master_session
            else:
                account_session = assume_role_in_account(acct['Id'],
                                 CROSS_ACCOUNT_ROLE_NAME, master_session
                )

            print(f'Searching WorkSpaces in account {acct["Id"]} ({acct["Name"]}):')

            for region in regions:
                try:
                    workspaces = find_workspaces(
                        region,
                        account_session,
                        acct['Id'],
                        acct['Name']
                    )
                    output_data.extend(workspaces)
                except (BotoCoreError, ClientError) as client_error:
                    print(f'Error searching region {region} '
                          f'in account {acct["Id"]}: {str(client_error)}')

        except (BotoCoreError, ClientError) as client_error:
            print(f'Error searching account {acct["Id"]}: {str(client_error)}')

    # Create a DataFrame and save it to an Excel file
    df = pd.DataFrame(output_data)

    # Create summary table
    summary_data = {
        'Total WorkSpaces': [len(df)]
    }

    for account in accounts:
        account_name_id = f'{account["Name"]} ({account["Id"]})'
        account_count = len(df[df['Account ID'] == account['Id']])
        summary_data[account_name_id] = [account_count]

    summary_table = pd.DataFrame(summary_data)

    # Save main table and summary table to the same Excel file
    with pd.ExcelWriter('WorkSpaces_Report-AllAccounts.xlsx', engine='xlsxwriter') as writer: # pylint: disable=abstract-class-instantiated
        df.to_excel(writer, sheet_name='WorkSpaces Details', index=False)
        summary_table.T.to_excel(writer, sheet_name='Summary', index=True, header=False)
