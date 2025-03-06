# AWS IAM User Analysis Script

This Python script is designed to analyze IAM user information within a specified AWS organization. It interacts with the AWS services using the `boto3` library and provides functionalities for fetching IAM user details, compiling them into a pandas DataFrame, and generating an Excel report. The main features of this script include:

- Retrieving AWS accounts from the organization.
- Assuming a role in each of these accounts to access IAM user information.
- Fetching IAM user attributes, such as user name, ARN, password status, last password change time, directly attached policies, and details about access keys.
- Compiling the fetched information into a structured pandas DataFrame.
- Generating an Excel report with IAM user details and a summary table.
- Applying conditional formatting to highlight cells in the Excel report.

## Script Execution

1. Install the required libraries by running:

   ```python
   pip install boto3 pandas xlsxwriter
   ```

2. Ensure your AWS credentials are properly configured. You can set up your credentials using the AWS CLI or by exporting environment variables.

3. Run the script using the following command:

   ```python
   python us_iam_query.py --profile_name <AWS_PROFILE_NAME>
   ```

4. Replace `<AWS_PROFILE_NAME>` with the name of the AWS profile configured in your `~/.aws/credentials` file.

## Script Workflow

1. The script starts by parsing command line arguments to determine the master account ID, master account name, and AWS profile name.

2. It retrieves the list of accounts in the AWS organization using the provided master account session.

3. The script removes the master account from the list and excludes specified account IDs.

4. For each account in the list, it assumes a role using the cross-account role name (`OrganizationAccountAccessRole`) and searches for IAM users in that account.

5. It calls the `process_single_user` function to retrieve information about each IAM user, including attributes like user name, ARN, password status, last password change time, directly attached policies, and access keys.

6. The fetched information is organized into a pandas DataFrame and saved to an Excel file named `US_IAM_Report-AllAccounts.xlsx`.

7. The script calculates the number of days since the last access key rotation for each user and generates a summary table with user counts for each account and additional statistics.

8. Conditional formatting is applied to highlight cells in the Excel report where the days since last rotation are greater than 90 days.

## Functions

- `get_login_profile(iam, user_name)`: Retrieves the login profile for a given IAM user, including password status and last password change time.
- `process_access_keys(iam, user_name)`: Retrieves and processes access keys for a given IAM user, including key ID, status, creation date, and last used date.
- `process_single_user(iam, user, acct_id, acct_name)`: Processes a single IAM user and retrieves relevant information.
- `find_iam_users(session, acct_id, acct_name)`: Searches for IAM users in a given AWS account and retrieves relevant information.
- `get_organization_accounts(master_sess)`: Retrieves a list of accounts in the AWS Organization.
- `assume_role_in_account(acc_id, role_name, session)`: Assumes a role in a specified AWS account using the provided session.

## Notes

- Ensure that the AWS profile being used has the necessary permissions to access the AWS Organization, IAM users, and their attributes.
- The script will generate an Excel file named `US_IAM_Report-AllAccounts.xlsx` containing detailed IAM user information and a summary table.
