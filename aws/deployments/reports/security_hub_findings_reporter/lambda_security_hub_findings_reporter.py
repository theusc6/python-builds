"""
Note 1: Be sure to replace the account number to reflect that of 
the Security Hub Delegated Administrator.

Note 2: Be sure to add the correct layer to the Lambda function in order to support Pandas.
AWSSDKPandas-Python311 is the current version and what is deployed with the deployment code.

Note 3: A second layer must be added for xlsxwriter. This will be a custom layer and the current 
version will be included in deployment code as well. New versions must be generated as needed.

Note 4: This function will typically require a timeout of 5 minutes and memory of 256.
"""

from datetime import datetime
import json
import io
import pandas as pd
import boto3
from botocore.exceptions import ClientError

def create_s3_bucket(bucket_name):
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
    s3_client = boto3.client('s3')

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
            CreateBucketConfiguration={'LocationConstraint': "ap-south-1"}
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

    log_bucket_name= "XXX-securityhub-s3.9accesslogging-162241159637-ap-south-1"

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

def export_security_hub_findings(bucket_name):
    """
    This function is designed to export all Security Hub findings to an XLSX file and upload
    """
    # Create a Security Hub client
    client = boto3.client('securityhub')
    # Create a paginator to retrieve all findings
    findings = []
    paginator = client.get_paginator('get_findings')

    # Includes only active, failed, unsuppressed findings for the report
    filters = {
        'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}],
        'WorkflowStatus': [{'Value': 'NEW', 'Comparison': 'EQUALS'}]
    }

    # Get all findings first
    for page in paginator.paginate(Filters=filters):
        findings.extend(page['Findings'])

    # Post-process the findings
    filtered_findings = []
    for finding in findings:
        if finding.get('ProductName', '') == 'Security Hub':
            if finding.get('Compliance', {}).get('Status', '') == 'FAILED':
                filtered_findings.append(finding)
        else:
            filtered_findings.append(finding)

    # Convert to DataFrame
    findings_df = pd.DataFrame(filtered_findings)
    if 'Severity' in findings_df.columns:
        findings_df['Severity'] = findings_df['Severity'].apply(lambda x: x.get('Label', 'Unknown'))
    else:
        print("Severity column not found")

    # Removing [' & '] from cells in the Types column
    findings_df['Types'] = findings_df['Types'].astype(str)
    findings_df['Types'] = (findings_df['Types']
                            .str.replace("['", '', regex=False)
                            .str.replace("']", '', regex=False))

    # Remove the columns "Sample", "SourceUrl", "GeneratorId",
    # "NetworkPath", and "FindingProviderFields"
    findings_df.drop([
        'Sample',
        'SourceUrl',
        'FindingProviderFields',
        'GeneratorId',
        'NetworkPath'
        ], axis=1, inplace=True, errors='ignore')

    # Extract the 'Url' value from the 'Remediation' column
    findings_df['Remediation'] = findings_df['Remediation'].apply(
        lambda x: x.get('Recommendation', {}).get('Url', 'N/A') if isinstance(x, dict) else 'N/A'
    )

    # Extract the 'Status' value from the 'Compliance' column
    findings_df['Compliance'] = findings_df['Compliance'].apply(
        lambda x: x.get('Status', 'N/A') if isinstance(x, dict) else 'N/A'
    )

    # Extract the 'Status' value from the 'Workfow' column
    findings_df['Workflow'] = findings_df['Workflow'].apply(
        lambda x: x.get('Status', 'N/A') if isinstance(x, dict) else 'N/A'
    )

    # Extract the 'Id' value from the 'Resources' column
    findings_df['Resources'] = findings_df['Resources'].apply(
    lambda x: (
        x[0].get('Id', 'N/A') if (
            isinstance(x, list) and len(x) > 0 and isinstance(x[0], dict)
        ) else 'N/A'
    ))

    # Extract the 'StandardsArn' or 'StandardsGuideArn' value from the 'ProductFields' column
    findings_df['ProductFields'] = findings_df['ProductFields'].apply(
    lambda x: (
        x.get('StandardsArn', x.get('StandardsGuideArn', 'N/A'))
        if isinstance(x, dict)
        else 'N/A'
    ))

    #Rename columns as needed
    findings_df.rename(columns={
    'ProductFields': 'Security Standard',
    'Id': 'Finding Id',
    }, inplace=True)

    # Group by AWS account ID
    grouped = findings_df.groupby('AwsAccountId')

    # Create BytesIO object
    output = io.BytesIO()

    # Initialize Excel writer
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:  # pylint: disable=abstract-class-instantiated
        # Write all instance details to one sheet
        findings_df.to_excel(writer, sheet_name='Instance Details', index=False)

        # Initialize variables to keep track of where to write the next summary
        start_row = 2
        sheet_name = 'Summary'

        # Initialize the DataFrame for the final summary
        final_columns = ['Inspector', 'Security Hub', 'GuardDuty', 'Health']
        final_index = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'Total']
        final_summary_df = pd.DataFrame(index=final_index, columns=final_columns).fillna(0)

        # Create a bold and italic format object
        bold_italic_format = writer.book.add_format({'bold': True, 'italic': True})

        for account_id, group in grouped:
            # Initialize an empty DataFrame to hold the summary
            columns = ['Inspector', 'Security Hub', 'GuardDuty', 'Health']
            index = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'Total']
            summary_df = pd.DataFrame(index=index, columns=columns).fillna(0)

            # Fill in the DataFrame based on group findings
            for column in columns:
                for severity in index[:-1]:  # Skip 'Total' for now
                    summary_df.loc[severity, column] = len(
                        group[
                            (group['Severity'] == severity) &
                            (group['ProductName'].str.contains(column, case=False))
                        ]
                    )

            # Compute and add the 'Total' for each column
            summary_df.loc['Total', :] = summary_df.sum(axis=0)

            # Update the final summary DataFrame
            for column in final_columns:
                for severity in final_index[:-1]:  # Skip 'Total' for now
                    final_summary_df.loc[severity, column] += summary_df.loc[severity, column]

            # Create a column that sums up the findings per severity level
            summary_df['Total Findings'] = summary_df.sum(axis=1) # pylint: disable=unsupported-assignment-operation

            # Write the summary DataFrame to the Excel file
            summary_df.to_excel(writer, sheet_name=sheet_name, startrow=start_row, index=True)

            # Add the account_id above the summary table
            worksheet = writer.sheets[sheet_name]
            worksheet.write(start_row-1, 0, f'Account ID: {account_id}', bold_italic_format)

            # Update the start row for the next summary
            start_row += len(summary_df) + 3  # +3 to leave an empty row between tables

        # Finalize the final summary DataFrame
        final_summary_df['Total Findings'] = final_summary_df.sum(axis=1) # pylint: disable=unsupported-assignment-operation
        final_summary_df.loc['Total', :] = final_summary_df.sum(axis=0)

        # Add the title above the final summary table
        final_summary_df.to_excel(writer, sheet_name=sheet_name, startrow=start_row, index=True)
        worksheet.write(start_row - 1, 0, 'Final Summary Across All Accounts', bold_italic_format)

    # Get Excel data
    output.seek(0)
    xlsx_data = output.read()

    # Create an S3 client
    s3client = boto3.client('s3')

    # Check if the bucket exists, create it if it doesn't
    if not any(bucket['Name'] == bucket_name for bucket in s3client.list_buckets()['Buckets']):
        create_s3_bucket(bucket_name)  # Call your bucket creation function here.

    # Generate a timestamp and format it as a string
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')

    # Get the current year and month
    current_year = datetime.now().strftime('%Y')
    current_month = datetime.now().strftime('%m')

    # Define the S3 resources
    base_folder = 'security-hub-findings-reports/'
    year_folder = f'{base_folder}{current_year}/'
    month_folder = f'{year_folder}{current_month}/'

    # Create year and month folders if they don't exist
    for folder in [base_folder, year_folder, month_folder]:
        s3client.put_object(Bucket=bucket_name, Key=f"{folder}")

    # Create the full filename
    filename = f'{month_folder}security_hub_findings_{timestamp}.xlsx'

    # Upload the XLSX file to S3
    s3client.put_object(Bucket=bucket_name, Key=filename, Body=xlsx_data)
    print(f'The latest Security Hub report, {filename}, has been generated and placed into '
        f'bucket {bucket_name} successfully!')    

    return {
        'statusCode': 200,
        'body': 'Security Hub findings exported successfully.'
    }

def main(event, context): # pylint: disable=unused-argument
    """
    Main function of script
    """
    bucket_name = 'XXX-securityhub-s3-findings-report-<account_id>-<region>'
    export_security_hub_findings(bucket_name)

if __name__ == '__main__':
    main() # pylint: disable=no-value-for-parameter
