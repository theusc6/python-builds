# Security Hub Findings Exporter

### Overview
This script will create the necessary resources to generate a weekly Security Hub Findings Report.

### Actions
This script will perform the following actions in the target account:

- Creates IAM role required for Lambda, SNS, KMS, etc.
- Creates KMS for data encryption to be used with SNS
- Creates the Lambda function that will be used to generate and parse the Securty Hub Findings Report
- Creates EventBridge Scheduler to invoke the function weekly on Mondays at 6:00AM PST
- Creates and assigns the triggers & layers reqiured for the Lambda function

### Usage
```
python export_security_hub_findings.py --profile <insert profile> --region <insert region> --account_id <insert account id>
```
### Target(s)
This script should only be ran in the delegated administrator account for Security Hub. This is the most efficient and cost effective target as it will maintain findings for all security tools and all AWS accounts in the organization. This will ensure that securtiy personnel have a single location from which to retrieve the findings report on a weekly basis. 

Please ensure that the Lambda code itself is updated with the correct regions and/or account numbers prior to deployment.

### Considerations
- An **Administrator** role is required to run this script.
- The Lambda code must still be uploaded to the Lambda function. Please ensure that script is secure, compliant, and properly updated. The runtime at this time is Python 3.11 and utilizes XLSX Writer to parse the report and display correctly. This layer may need to be updated over time or as required by security.
- The "Timeout" and "Memory" values for the Lambda function should be modified to meet the requirements of your environment. As an example, the India tenant accepts the minimum configuration whereas the US tenant requires the maxmimum timeout (900 seconds) and a memory size of 1024Mb. These values will change based on the number of total findings, number of accounts, etc.
