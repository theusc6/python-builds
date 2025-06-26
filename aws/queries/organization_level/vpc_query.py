"""
This module is used to perform operations on AWS services using the boto3 library.
It interacts with AWS VPCs across organizational accounts, retrieves data, and 
stores it in a pandas DataFrame, which is then exported to an Excel file.

The script executes the following tasks:
1. Retrieves the list of accounts in the AWS organization.
2. Excludes certain accounts based on their IDs.
3. Assumes a role in each account to gain the permissions necessary to list all VPCs.
4. Searches all specified AWS regions for VPCs in each account.
5. Retrieves and prints relevant details about each VPC, such as its ID, Name, 
   State, CIDR blocks, Region, and the Account it belongs to.
6. Checks VPC Flow Logs status and configuration.
7. Stores the retrieved data in a pandas DataFrame.
8. Generates a summary of VPC details.
9. Writes the DataFrame and the summary to separate sheets in an Excel file.

Functions:
    get_vpc_name: Retrieves the name of a VPC from its tags.
    get_vpc_subnets: Retrieves subnet information for a VPC.
    get_vpc_flow_logs: Retrieves VPC Flow Logs information.
    find_vpcs: Finds and prints VPCs in a given region and account.
    get_organization_accounts: Retrieves a list of accounts in the organization.
    assume_role_in_account: Assumes a role in a specified account to gain permissions.
"""
import argparse
import boto3
import pandas as pd
from botocore.exceptions import BotoCoreError, ClientError

def get_vpc_name(vpc):
    """
    Retrieves the name of a VPC from its tags.

    Parameters:
    vpc (boto3.EC2.Vpc): A VPC resource.

    Returns:
    str: The value of the 'Name' tag if it exists, 'N/A' otherwise.
    """
    if vpc.tags:
        for tag in vpc.tags:
            if tag['Key'] == 'Name':
                return tag['Value']
    return 'N/A'

def get_vpc_subnets(ec2_client, vpc_id):
    """
    Retrieves subnet information for a VPC.

    Parameters:
    ec2_client (boto3.client): EC2 client object.
    vpc_id (str): VPC ID.

    Returns:
    tuple: (subnet_count, public_subnet_count, private_subnet_count)
    """
    try:
        subnets_response = ec2_client.describe_subnets(
            Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
        )
        subnets = subnets_response['Subnets']

        subnet_count = len(subnets)
        public_subnet_count = 0
        private_subnet_count = 0

        # Check route tables to determine if subnets are public or private
        route_tables_response = ec2_client.describe_route_tables(
            Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
        )

        public_subnet_ids = set()
        for rt in route_tables_response['RouteTables']:
            # Check if route table has internet gateway route
            has_igw = any(
                route.get('GatewayId', '').startswith('igw-')
                for route in rt['Routes']
            )
            if has_igw:
                # Add associated subnets to public set
                for association in rt['Associations']:
                    if 'SubnetId' in association:
                        public_subnet_ids.add(association['SubnetId'])

        for subnet in subnets:
            if subnet['SubnetId'] in public_subnet_ids:
                public_subnet_count += 1
            else:
                private_subnet_count += 1

        return subnet_count, public_subnet_count, private_subnet_count
    except ClientError as e:
        print(f"Error retrieving subnets for VPC {vpc_id}: {str(e)}")
        return 0, 0, 0

def debug_all_flow_logs(ec2_client):
    """Debug helper to show all flow logs in the region."""
    try:
        all_flow_logs_response = ec2_client.describe_flow_logs()
        all_flow_logs = all_flow_logs_response['FlowLogs']
        print(f"DEBUG: Total flow logs in region: {len(all_flow_logs)}")

        # Show all flow logs for debugging
        for fl in all_flow_logs:
            print(f"DEBUG: Flow Log ID: {fl.get('FlowLogId')}, "
                  f"Resource: {fl.get('ResourceId')}, "
                  f"Type: {fl.get('LogDestinationType', 'Unknown')}, "
                  f"Status: {fl.get('FlowLogStatus')}, "
                  f"Traffic: {fl.get('TrafficType')}")

    except ClientError as debug_error:
        print(f"DEBUG: Cannot retrieve all flow logs for debugging: {debug_error}")

def check_subnet_flow_logs(ec2_client, vpc_id, all_logs):
    """Check for flow logs on subnets within the VPC."""
    try:
        subnets_response = ec2_client.describe_subnets(
            Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
        )
        subnet_ids = [subnet['SubnetId'] for subnet in subnets_response['Subnets']]

        subnet_flow_logs = [fl for fl in all_logs if fl.get('ResourceId') in subnet_ids]
        print(f"DEBUG: Found {len(subnet_flow_logs)} flow logs for subnets in VPC {vpc_id}")

        if subnet_flow_logs:
            print(f"DEBUG: VPC {vpc_id} has flow logs on subnets but not VPC level")

    except ClientError as subnet_error:
        print(f"DEBUG: Cannot check subnet flow logs: {subnet_error}")

def parse_flow_log_destination(flow_log):
    """Parse flow log destination information."""
    dest_type = flow_log.get('LogDestinationType', '')
    if dest_type == 'cloud-watch-logs':
        return f"CloudWatch Logs: {flow_log.get('LogGroupName', 'Unknown')}"
    if dest_type == 's3':
        return f"S3: {flow_log.get('LogDestination', 'Unknown')}"
    if dest_type == 'kinesis-data-firehose':
        return f"Kinesis Data Firehose: {flow_log.get('LogDestination', 'Unknown')}"

    # For backward compatibility, check if it's CloudWatch Logs without LogDestinationType
    if flow_log.get('LogGroupName'):
        return f"CloudWatch Logs: {flow_log.get('LogGroupName')}"
    if flow_log.get('LogDestination'):
        return f"Unknown Type: {flow_log.get('LogDestination')}"

    return "Unknown"

def process_flow_logs(flow_logs, vpc_id):
    """Process flow logs and extract relevant information."""
    flow_log_types = []
    destinations = []
    delivery_statuses = []

    for flow_log in flow_logs:
        print(f"DEBUG: Processing flow log {flow_log.get('FlowLogId')} - "
              f"Status: {flow_log.get('FlowLogStatus')}, "
              f"Type: {flow_log.get('LogDestinationType')}, "
              f"Traffic: {flow_log.get('TrafficType')}")

        # Get traffic type (ALL, ACCEPT, REJECT)
        traffic_type = flow_log.get('TrafficType', 'Unknown')
        flow_log_types.append(traffic_type)

        # Get destination information
        destination = parse_flow_log_destination(flow_log)
        destinations.append(destination)

        # Get delivery status
        delivery_status = flow_log.get('DeliverLogsStatus', 'Unknown')
        delivery_statuses.append(delivery_status)

    # Join multiple values with semicolons if there are multiple flow logs
    flow_log_types_str = '; '.join(set(flow_log_types))
    destinations_str = '; '.join(destinations)
    delivery_statuses_str = '; '.join(set(delivery_statuses))

    print(f"DEBUG: Final result for VPC {vpc_id}: "
          f"Enabled=True, Types={flow_log_types_str}, "
          f"Destinations={destinations_str}, Status={delivery_statuses_str}")

    return flow_log_types_str, destinations_str, delivery_statuses_str

def get_vpc_flow_logs(ec2_client, vpc_id):
    """
    Retrieves VPC Flow Logs information for a VPC.

    Parameters:
    ec2_client (boto3.client): EC2 client object.
    vpc_id (str): VPC ID.

    Returns:
    tuple: (flow_logs_enabled, flow_log_types, destinations, delivery_statuses)
    """
    try:
        print(f"DEBUG: Checking flow logs for VPC {vpc_id}")

        # First, try to get ALL flow logs to see what's available
        debug_all_flow_logs(ec2_client)

        # Now try to get flow logs for specific VPC
        print(f"DEBUG: Trying resource-id filter only for {vpc_id}")

        # Approach 1: Just resource-id filter
        flow_logs_response = ec2_client.describe_flow_logs(
            Filters=[
                {'Name': 'resource-id', 'Values': [vpc_id]}
            ]
        )

        flow_logs = flow_logs_response['FlowLogs']
        print(f"DEBUG: Found {len(flow_logs)} flow logs with resource-id filter")

        # If no results, try without any filters and manually filter
        if not flow_logs:
            print("DEBUG: No flow logs found with filter, checking all flow logs manually")
            all_response = ec2_client.describe_flow_logs()
            all_logs = all_response['FlowLogs']

            # Manually filter for our VPC
            flow_logs = [fl for fl in all_logs if fl.get('ResourceId') == vpc_id]
            print(f"DEBUG: Found {len(flow_logs)} flow logs after manual filtering")

            # Also check for any flow logs that might be related to subnets in this VPC
            check_subnet_flow_logs(ec2_client, vpc_id, all_logs)

        if not flow_logs:
            print(f"DEBUG: No flow logs found for VPC {vpc_id} at any level")
            return False, 'None', 'None', 'None'

        print(f"DEBUG: Processing {len(flow_logs)} flow log(s) for VPC {vpc_id}")

        # Process the flow logs
        flow_log_types_str, destinations_str,delivery_statuses_str = process_flow_logs(
            flow_logs, vpc_id)

        return True, flow_log_types_str, destinations_str, delivery_statuses_str

    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_message = e.response.get('Error', {}).get('Message', str(e))

        print(f"DEBUG: ClientError for VPC {vpc_id}: {error_code} - {error_message}")

        if error_code == 'UnauthorizedOperation':
            print(f"DEBUG: No permission to describe flow logs for VPC {vpc_id}")
            return False, 'No Permission', 'No Permission', 'No Permission'

        print(f"Error retrieving flow logs for VPC {vpc_id}: {str(e)}")
        return False, 'Error', 'Error', 'Error'

def get_vpc_cidr_blocks(vpc):
    """Get all CIDR blocks for a VPC."""
    cidr_blocks = [vpc.cidr_block]
    if hasattr(vpc, 'cidr_block_association_set'):
        for cidr_assoc in vpc.cidr_block_association_set:
            if cidr_assoc['CidrBlock'] != vpc.cidr_block:
                cidr_blocks.append(cidr_assoc['CidrBlock'])
    return cidr_blocks

def get_vpc_gateway_info(ec2_client, vpc_id):
    """Get internet gateway and NAT gateway information for a VPC."""
    # Get internet gateway information
    igw_response = ec2_client.describe_internet_gateways(
        Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}]
    )
    has_internet_gateway = bool(igw_response['InternetGateways'])

    # Get NAT gateway information
    nat_response = ec2_client.describe_nat_gateways(
        Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
    )
    nat_gateway_count = len(nat_response['NatGateways'])

    return has_internet_gateway, nat_gateway_count

def create_vpc_record(vpc, vpc_details, aws_region, account_id, account_name_param):
    """Create a VPC record dictionary from VPC and collected details."""
    return {
        'VPC ID': vpc.id,
        'Name': vpc_details['vpc_name'],
        'State': vpc.state,
        'Is Default': vpc.is_default,
        'VPC Owner ID': vpc.owner_id,
        'Ownership Status': vpc_details['ownership_status'],
        'CIDR Blocks': ', '.join(vpc_details['cidr_blocks']),
        'Subnet Count': vpc_details['subnet_count'],
        'Public Subnets': vpc_details['public_subnets'],
        'Private Subnets': vpc_details['private_subnets'],
        'Has Internet Gateway': vpc_details['has_internet_gateway'],
        'NAT Gateway Count': vpc_details['nat_gateway_count'],
        'Flow Logs Enabled': vpc_details['flow_logs_enabled'],
        'Flow Log Types': vpc_details['flow_log_types'],
        'Flow Log Destinations': vpc_details['flow_log_destinations'],
        'Flow Log Status': vpc_details['flow_log_status'],
        'Region': aws_region,
        'Account ID': account_id,
        'Account Name': account_name_param
    }

def print_vpc_info(vpc, vpc_details, aws_region, account_id):
    """Print VPC information to console."""
    print(f'Found VPC - ID: {vpc.id}, '
          f'Name: {vpc_details["vpc_name"]}, '
          f'State: {vpc.state}, '
          f'Default: {vpc.is_default}, '
          f'Owner: {vpc.owner_id} ({vpc_details["ownership_status"]}), '
          f'CIDR: {", ".join(vpc_details["cidr_blocks"])}, '
          f'Subnets: {vpc_details["subnet_count"]} '
          f'(Public: {vpc_details["public_subnets"]}, Private: {vpc_details["private_subnets"]}), '
          f'Flow Logs: {vpc_details["flow_logs_enabled"]} ({vpc_details["flow_log_types"]}), '
          f'Region: {aws_region}, '
          f'Account: {account_id}')

def find_vpcs(aws_region, session, account_id, account_name_param):
    """
    Retrieves and prints the details of all VPCs within a 
    specific region for a given account.

    Parameters:
    aws_region (str): The name of the region where VPCs are located.
    session (boto3.Session): A valid boto3 Session object.
    account_id (str): The AWS account ID where VPCs are located.
    account_name_param (str): The name associated with the AWS account.

    Returns:
    list: A list of dictionaries, where each dictionary contains details of a VPC.
    """
    try:
        ec2 = session.resource('ec2', region_name=aws_region)
        ec2_client = session.client('ec2', region_name=aws_region)
        vpcs = ec2.vpcs.all()

        data = []
        for vpc in vpcs:
            # Collect all VPC details
            vpc_details = {
                'vpc_name': get_vpc_name(vpc),
                'ownership_status': "Shared" if vpc.owner_id != account_id else "Owned",
                'cidr_blocks': get_vpc_cidr_blocks(vpc)
            }

            # Get subnet information
            subnet_info = get_vpc_subnets(ec2_client, vpc.id)
            vpc_details.update({
                'subnet_count': subnet_info[0],
                'public_subnets': subnet_info[1],
                'private_subnets': subnet_info[2]
            })

            # Get gateway information
            gateway_info = get_vpc_gateway_info(ec2_client, vpc.id)
            vpc_details.update({
                'has_internet_gateway': gateway_info[0],
                'nat_gateway_count': gateway_info[1]
            })

            # Get flow logs information
            flow_log_info = get_vpc_flow_logs(ec2_client, vpc.id)
            vpc_details.update({
                'flow_logs_enabled': flow_log_info[0],
                'flow_log_types': flow_log_info[1],
                'flow_log_destinations': flow_log_info[2],
                'flow_log_status': flow_log_info[3]
            })

            # Create record and add to data
            vpc_record = create_vpc_record(vpc, vpc_details, aws_region,
                                           account_id, account_name_param)
            data.append(vpc_record)

            # Print VPC information
            print_vpc_info(vpc, vpc_details, aws_region, account_id)

        return data
    except ClientError as client_error:
        if client_error.response['Error']['Code'] == 'UnauthorizedOperation':
            print(f"Unauthorized operation in region {aws_region}: {str(client_error)}")
        else:
            print(f"Unexpected error in region {aws_region}: {str(client_error)}")
        return []  # return empty list if error occurs

def get_organization_accounts(master_sess):
    """
    Fetches a list of accounts in the organization using the provided session.

    Args:
        master_sess (boto3.Session): A session object which 
        represents a configuration state for operations.

    Returns:
        accounts (list): A list of dictionaries, each containing 
        the ID and Name of an account in the organization.
    """
    organizations = master_sess.client('organizations')
    paginator = organizations.get_paginator('list_accounts')
    accounts_list = []

    for page in paginator.paginate():
        accounts_list.extend(page['Accounts'])

    for account in accounts_list:
        print(f'Account ID: {account["Id"]}, Name: {account["Name"]}')

    return accounts_list

def assume_role_in_account(account_id, role_name, session):
    """
    Assumes a role in the given account and creates a new 
    session with the assumed role's credentials.

    Args:
        account_id (str): The ID of the AWS account where the role is to be assumed.
        role_name (str): The name of the role to be assumed.
        session (boto3.Session): The existing boto3 session from which STS client is created.

    Returns:
        boto3.Session: A new boto3 Session object with the assumed role's credentials.
    """
    try:
        print(f'\nAssuming role in account '
              f'{account_id}: arn:aws:iam::{account_id}:role/{role_name}')
        sts = session.client('sts')
        response = sts.assume_role(
            RoleArn=f'arn:aws:iam::{account_id}:role/{role_name}',
            RoleSessionName='VPCReportGenerator'
        )

        return boto3.Session(
            aws_access_key_id=response['Credentials']['AccessKeyId'],
            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
            aws_session_token=response['Credentials']['SessionToken']
        )
    except ClientError as client_error:
        print(f"Failed to assume role in account {account_id}. Error: {str(client_error)}")
        return None

def parse_arguments():
    """
    Parse command line arguments.
    """
    parser = argparse.ArgumentParser(
        description="Script to generate AWS VPC report."
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
        "--profile_name", "-p",
        required=True,
        default="n/a",
        help="AWS profile name. Default: default"
    )

    return parser.parse_args()

if __name__ == '__main__':
    args = parse_arguments()

    PROFILE_NAME = args.profile_name
    master_session = boto3.Session(profile_name=args.profile_name)
    regions = [
        "us-west-2",
        "us-east-1",
        "us-east-2",
        "eu-west-2",
        "ap-southeast-1",
        "ap-east-1"
    ]
    accounts = get_organization_accounts(master_session)
    print(f'Found {len(accounts)} accounts in the organization.')
    CROSS_ACCOUNT_ROLE_NAME = 'OrganizationAccountAccessRole'

    # Add master account to the list of accounts
    MASTER_ACCOUNT_ID = args.master_account_id
    MASTER_ACCOUNT_NAME = args.master_account_name
    master_account = {'Id': MASTER_ACCOUNT_ID, 'Name': MASTER_ACCOUNT_NAME}

    # Add excluded account IDs - these are excluded due to 'suspended' status.
    # Accounts will be deleted in 90 days from suspension date
    excluded_account_ids = []

    # Remove the master account and excluded accounts from the list
    accounts = [account for account in accounts if account['Id'] != MASTER_ACCOUNT_ID
                and account['Id'] not in excluded_account_ids]
    accounts.append(master_account)

    # Iterate through the accounts, assume role, and find VPCs
    output_data = []
    for acct in accounts:
        try:
            if acct['Id'] == MASTER_ACCOUNT_ID:
                account_session = master_session
            else:
                account_session = assume_role_in_account(acct['Id'],
                                                       CROSS_ACCOUNT_ROLE_NAME, master_session)

            if account_session is None:
                print(f"Skipping account {acct['Id']} due to error in assuming role.")
                continue

            print(f'Searching VPCs in account {acct["Id"]} ({acct["Name"]}):')

            for region in regions:
                try:
                    output_data.extend(
                        find_vpcs(
                            region,
                            account_session,
                            acct['Id'],
                            acct['Name']
                        )
                    )
                except BotoCoreError as e:
                    print(f'Error searching region {region} in account {acct["Id"]}: {str(e)}')

        except BotoCoreError as e:
            print(f'Error searching account {acct["Id"]}: {str(e)}')

    # Create a DataFrame and save it to an Excel file
    df = pd.DataFrame(output_data)

    # Check if DataFrame is empty
    if df.empty:
        print("No VPCs found across all accounts and regions.")
        print("Creating empty report...")

        # Create empty summary for no data
        summary_data = {
            'Total VPCs': [0],
            'Owned VPCs': [0],
            'Shared VPCs': [0],
            'Default VPCs': [0],
            'Custom VPCs': [0],
            'VPCs with Internet Gateway': [0],
            'VPCs with NAT Gateway': [0],
            'VPCs with Flow Logs Enabled': [0],
            'VPCs without Flow Logs': [0],
            'Total Subnets': [0],
            'Total Public Subnets': [0],
            'Total Private Subnets': [0]
        }
    else:
        # Create summary table with data
        summary_data = {
            'Total VPCs': [len(df)],
            'Owned VPCs': [len(df[df['Ownership Status'] == 'Owned'])],
            'Shared VPCs': [len(df[df['Ownership Status'] == 'Shared'])],
            'Default VPCs': [len(df[df['Is Default']])],
            'Custom VPCs': [len(df[~df['Is Default']])],
            'VPCs with Internet Gateway': [len(df[df['Has Internet Gateway']])],
            'VPCs with NAT Gateway': [len(df[df['NAT Gateway Count'] > 0])],
            'VPCs with Flow Logs Enabled': [len(df[df['Flow Logs Enabled']])],
            'VPCs without Flow Logs': [len(df[~df['Flow Logs Enabled']])],
            'Total Subnets': [df['Subnet Count'].sum()],
            'Total Public Subnets': [df['Public Subnets'].sum()],
            'Total Private Subnets': [df['Private Subnets'].sum()]
        }

    # Add per-region details (only if DataFrame is not empty)
    if not df.empty:
        for region in regions:
            region_data = df[df['Region'] == region]
            owned_vpcs = region_data[region_data['Ownership Status'] == 'Owned']
            shared_vpcs = region_data[region_data['Ownership Status'] == 'Shared']

            summary_data[f'{region} VPCs'] = [len(region_data)]
            summary_data[f'{region} Owned VPCs'] = [len(owned_vpcs)]
            summary_data[f'{region} Shared VPCs'] = [len(shared_vpcs)]
            summary_data[f'{region} Default VPCs'] = [len(region_data[region_data['Is Default']])]
            summary_data[f'{region} Custom VPCs'] = [len(region_data[~region_data['Is Default']])]
            summary_data[f'{region} Flow Logs Enabled'] = [
                len(region_data[region_data['Flow Logs Enabled']])
            ]
            summary_data[f'{region} Subnets'] = [region_data['Subnet Count'].sum()]

        # Add per-account summary
        account_summary = df.groupby('Account Name').agg({
            'VPC ID': 'count',
            'Subnet Count': 'sum',
            'Public Subnets': 'sum',
            'Private Subnets': 'sum',
            'Flow Logs Enabled': 'sum'
        }).to_dict()

        for account_name in df['Account Name'].unique():
            summary_data[f'{account_name} VPCs'] = [
                account_summary['VPC ID'][account_name]
            ]
            summary_data[f'{account_name} Total Subnets'] = [
                account_summary['Subnet Count'][account_name]
            ]
            summary_data[f'{account_name} Flow Logs Enabled'] = [
                account_summary['Flow Logs Enabled'][account_name]
            ]

    # Convert to DataFrame for Excel output
    summary_table = pd.DataFrame(summary_data)

    # Save main table and summary table to the same Excel file
    with pd.ExcelWriter('AWS_VPC_Report-AllRegions.xlsx') as writer:
        df.to_excel(writer, sheet_name='VPC Details', index=False)
        summary_table.T.to_excel(writer, sheet_name='Summary', index=True, header=['Count'])

    print("\nReport generated successfully!")
    print(f"Total VPCs found: {len(df)}")
    if not df.empty:
        flow_logs_enabled = len(df[df['Flow Logs Enabled']])
        flow_logs_disabled = len(df[~df['Flow Logs Enabled']])
        print(f"VPCs with Flow Logs enabled: {flow_logs_enabled}")
        print(f"VPCs without Flow Logs: {flow_logs_disabled}")
    else:
        print("VPCs with Flow Logs enabled: 0")
        print("VPCs without Flow Logs: 0")
    print("Report saved to: AWS_VPC_Report-AllRegions.xlsx")
