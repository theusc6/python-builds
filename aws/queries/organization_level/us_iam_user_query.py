"""
This module contains a collection of functions used to analyze IAM user information 
in a given AWS organization. The main functionalities of this script include:

- Fetching AWS accounts from the organization
- Assuming a role in each of these accounts
- Fetching IAM user information for each account
- Compiling this information into a pandas DataFrame
- Writing this DataFrame to an Excel file, along with a summary table
- Applying conditional formatting to the Excel file
"""
from datetime import datetime
import argparse
import boto3
import pandas as pd
from botocore.exceptions import BotoCoreError, ClientError

DAYS_SINCE_LAST_ROTATION = "Days Since Last Rotation"
ACCESS_KEY_CREATED_DATE = "Access Key Created Date"

def get_login_profile(iam, user_name):
    """
    Retrieves the login profile for a given IAM user.

    This function uses the `get_login_profile` method of the AWS IAM service to fetch 
    information about a user's login profile. It checks if the user has a password 
    enabled and retrieves the date when the password was last changed.

    If the user does not have a login profile (which is indicated by a 
    `NoSuchEntityException`), the function assumes that a password is not enabled for 
    the user and sets the `password_last_changed` to 'N/A'.

    Args:
        iam (boto3.IAM): The IAM resource object for the account.
        user_name (str): The name of the IAM user.

    Returns:
        tuple: A tuple containing two elements:
            - password_enabled (bool): True if the user has a password enabled, False otherwise.
            - password_last_changed (datetime or str): The date and time when the password 
              was last changed, or 'N/A' if a password is not enabled.
    """
    try:
        login_profile = iam.get_login_profile(UserName=user_name)
        password_enabled = True
        login_profile_create_date = login_profile['LoginProfile']['CreateDate']
        password_last_changed = login_profile_create_date.replace(tzinfo=None)
    except iam.exceptions.NoSuchEntityException:
        password_enabled = False
        password_last_changed = 'N/A'
    return password_enabled, password_last_changed

def process_access_keys(iam, user_name):
    """
    Retrieves and processes access keys for a given IAM user.

    This function uses the `list_access_keys` and `get_access_key_last_used` methods of 
    the AWS IAM service to fetch and process information about a user's access keys. It 
    constructs a list of dictionaries containing key ID, status, creation date, and the 
    last used date for each access key associated with the user.

    Args:
        iam (boto3.IAM): The IAM resource object for the account.
        user_name (str): The name of the IAM user.

    Returns:
        list: A list of dictionaries, each containing information about an access key:
            - 'Access Key ID' (str): The ID of the access key.
            - 'Access Key Status' (str): The status of the access key ('Active' or 'Inactive').
            - 'Access Key Created Date' (datetime): The date and time when the key was created.
            - 'Access Key Last Used' (datetime or str): 
            The date and time when the key was last used, 
              or 'N/A' if the key has not been used.
    """
    access_keys = iam.list_access_keys(UserName=user_name)
    keys_data = []
    for access_key in access_keys['AccessKeyMetadata']:
        access_key_id = access_key['AccessKeyId']
        access_key_status = access_key['Status']
        access_key_created_date = access_key['CreateDate'].replace(tzinfo=None)
        access_key_last_used_response = iam.get_access_key_last_used(
            AccessKeyId=access_key_id
        )
        access_key_last_used = access_key_last_used_response.get(
            'AccessKeyLastUsed', {}).get('LastUsedDate', 'N/A'
        )
        if access_key_last_used != 'N/A':
            access_key_last_used = access_key_last_used.replace(tzinfo=None)
        keys_data.append({
            'Access Key ID': access_key_id, 
            'Access Key Status': access_key_status,
            ACCESS_KEY_CREATED_DATE: access_key_created_date,
            'Access Key Last Used': access_key_last_used
        })
    return keys_data

def process_single_user(iam, user, acct_id, acct_name):
    """
    Processes a single IAM user and retrieves relevant information.

    This function fetches various attributes of an IAM user, including the user's name,
    ARN, password status, last password change time, directly attached policies, and 
    details about all access keys. It calls `get_login_profile` to retrieve information 
    about the user's password, and `process_access_keys` to retrieve information about 
    the user's access keys. The returned data is structured as a list of dictionaries, 
    each corresponding to an access key of the user and containing information about 
    the user and the access key.

    Args:
        iam (botocore.client.IAM): The IAM client object.
        user (dict): The IAM user.
        acct_id (str): The ID of the AWS account.
        acct_name (str): The name of the AWS account.

    Returns:
        list: A list of dictionaries, each representing an access key of the user and 
              containing information about the user and the access key.
    """
    user_name = user['UserName']
    user_arn = user['Arn']
    print(f'Found IAM User - Name: {user_name}, ARN: {user_arn}, Account: {acct_id}')

    password_enabled, password_last_changed = get_login_profile(iam, user_name)

    attached_policies = iam.list_attached_user_policies(UserName=user_name)
    attached_policy_names = [
        policy['PolicyName'] for policy in attached_policies['AttachedPolicies']
    ]

    keys_data = process_access_keys(iam, user_name)

    user_data = []
    for key_data in keys_data:
        data = {
            'User Name': user_name,
            'User ARN': user_arn,
            'Account ID': acct_id,
            'Account Name': acct_name,
            'Password Enabled': password_enabled,
            'Password Last Changed': password_last_changed,
            'Directly Attached Policies': ', '.join(attached_policy_names),
        }
        data.update(key_data)
        user_data.append(data)

    return user_data


def find_iam_users(session, acct_id, acct_name):
    """
    Searches for IAM users in the given AWS account and retrieves relevant information.

    This function uses the `list_users` method of the AWS IAM service to fetch users from 
    a given account. It then processes each user by calling `process_single_user`, which 
    retrieves and organizes information about the user's attributes such as the username, 
    ARN, password status, last password change time, directly attached policies, and details 
    about all access keys. All this information is returned as a list of dictionaries, each 
    corresponding to an access key of a user.

    Args:
        session (boto3.Session): The Boto3 session object.
        acct_id (str): The ID of the AWS account.
        acct_name (str): The name of the AWS account.

    Returns:
        list: A list of dictionaries, each representing an access key of a user and containing 
              information about the user and the access key.
    """
    iam = session.client('iam')
    paginator = iam.get_paginator('list_users')
    data = []

    for page in paginator.paginate():
        for user in page['Users']:
            user_data = process_single_user(iam, user, acct_id, acct_name)
            data.extend(user_data)

    return data


def get_organization_accounts(master_sess):
    """
    Retrieves a list of accounts in the AWS Organization.

    Args:
        master_session (boto3.Session): The Boto3 session object for the master account.

    Returns:
        list: A list of dictionaries containing account information.
    """
    organizations = master_sess.client('organizations')
    paginator = organizations.get_paginator('list_accounts')
    accounts_list = []

    for page in paginator.paginate():
        accounts_list.extend(page['Accounts'])

    for account_item in accounts_list:
        print(f'Account ID: {account_item["Id"]}, Name: {account_item["Name"]}')

    return accounts_list

def col_num_to_letter(col_num):
    """
    Converts a column number to its corresponding letter representation.

    Args:
        col_num (int): The column number to convert.

    Returns:
        str: The corresponding letter representation of the column number.
    """
    string = ""
    while col_num > 0:
        col_num, remainder = divmod(col_num - 1, 26)
        string = chr(65 + remainder) + string
    return string

def assume_role_in_account(acc_id, role_name, session):
    """
    Assumes a role in a specified AWS account using the provided session.

    Args:
        account_id (str): The ID of the AWS account in which to assume the role.
        role_name (str): The name of the role to assume.
        master_session (boto3.Session): The master session used for assuming the role.

    Returns:
        boto3.Session: The session with the assumed role.

    """
    print(f'\nAssuming role in account {acc_id}: '
          f'arn:aws:iam::{acc_id}:role/{role_name}')
    sts = session.client('sts')
    response = sts.assume_role(
        RoleArn=f'arn:aws:iam::{acc_id}:role/{role_name}',
        RoleSessionName='IAMUserFinder'
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
        default=" ",
        help="AWS Master account id. Default: "
    )

    parser.add_argument(
        "--master_account_name",
        default="",
        help="AWS Master account name. Default: "
    )

    parser.add_argument(
        '-p',
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
    accounts = get_organization_accounts(master_session)
    print(f'Found {len(accounts)} accounts in the organization.')
    CROSS_ACCOUNT_ROLE_NAME = 'OrganizationAccountAccessRole'

    # Add master account to the list of accounts
    MASTER_ACCOUNT_ID = args.master_account_id
    MASTER_ACCOUNT_NAME = args.master_account_name
    master_account = {'Id': MASTER_ACCOUNT_ID, 'Name': MASTER_ACCOUNT_NAME}

    # Remove the master account from the list
    accounts = [account for account in accounts if account['Id'] != MASTER_ACCOUNT_ID]
    accounts.append(master_account)

    # Add excluded account IDs, if applicable
    excluded_account_ids = []
    # Exclude the specified accounts from the list
    accounts = [account for account in accounts if account['Id'] not in excluded_account_ids]

    # Iterate through the accounts, assume role, and find IAM users
    output_data = []
    for acct in accounts:
        try:
            if acct['Id'] == MASTER_ACCOUNT_ID:
                account_session = master_session
            else:
                temp_account_id = acct['Id']
                account_session = assume_role_in_account(
                    temp_account_id,
                    CROSS_ACCOUNT_ROLE_NAME,
                    master_session
                )

            print(f'Searching IAM users in account {acct["Id"]} ({acct["Name"]}):')
            output_data.extend(find_iam_users(account_session, acct['Id'], acct['Name']))
        except (BotoCoreError, ClientError) as client_error:
            print(f'Error searching account {acct["Id"]}: {str(client_error)}')

    # Create a DataFrame and save it to an Excel file
    df = pd.DataFrame(output_data)

    # Calculate the number of days since the last access key rotation for each user
    df[ACCESS_KEY_CREATED_DATE] = pd.to_datetime(df[ACCESS_KEY_CREATED_DATE])
    df[DAYS_SINCE_LAST_ROTATION] = (datetime.now() - df[ACCESS_KEY_CREATED_DATE]).dt.days


    # Create summary table
    summary_data = {
        'Total IAM Users': [len(df)]
    }

    for account in accounts:
        account_name = account["Name"]
        account_id = account["Id"]
        users_count = len(df[df['Account ID'] == account_id])
        summary_data[f'{account_name} ({account_id})'] = [users_count]


    users_greater_than_90 = len(df[df[DAYS_SINCE_LAST_ROTATION] > 90])
    summary_data['Users with > 90 Days Since Rotation'] = [users_greater_than_90]
    summary_table = pd.DataFrame(summary_data)

    # Save main table and summary table to the same Excel file
    with pd.ExcelWriter('US_IAM_Report-AllAccounts.xlsx', engine='xlsxwriter') as writer: # pylint: disable=abstract-class-instantiated
        df.to_excel(writer, sheet_name='IAM User Details', index=False)
        summary_table.T.to_excel(writer, sheet_name='Summary', index=True, header=False)

        # Apply conditional formatting to highlight cells with > 90 days since rotation
        workbook = writer.book
        worksheet = writer.sheets['IAM User Details']
        red_format = workbook.add_format({'bg_color': '#FFC7CE', 'font_color': '#9C0006'})
        days_since_last_rotation_col_letter = col_num_to_letter(
            df.columns.get_loc(DAYS_SINCE_LAST_ROTATION) + 1
        )

        range_string = (
            f'{days_since_last_rotation_col_letter}2:'
            f'{days_since_last_rotation_col_letter}{len(df) + 1}'
        )

        worksheet.conditional_format(
            range_string,
            {'type': 'cell', 'criteria': '>', 'value': 90, 'format': red_format}
        )
