# Inspector Deployer

## Overview

This script will activate & deploy AWS Inspector to a specified AWS Account with all required and fully-compliant depedencies. In addition, this script will also ensure that all Ec2 instances are assigned the correct Instance Profile so that they can be properly managed by AWS Inspector. 

## Actions
A full list of actions taken by this script can be found below:
-  Creation of the default role for Systems Manager (SSM)
-  Enables Default Host Management for SSM, which allows for automatic management for future Ec2 instances, no instance profile required
-  Assings the above role to all Ec2 instances in the target account
-  Enables AWS Inspector v2 in the target account
-  Creates the IAM role needed for Amazon Inspector
-  Creates the KMS key required for the findings report (enables key rotation if not already)
-  Creates the target S3 bucket that will receive the findings report (fully compliant bucket)
-  Creates EventBridge Scheduler to run this report each Monday at 6:00AM PST
-  When the script is ran, it will run a report of findings immediately. The next report will be generated at the above scheduled time.

## Usage
This script can be ran by the following command:

```
python inspector_deployer.py --profile <insert profile> --region <insert region>
```

## Target(s)
This script should be ran in all AWS accounts when:
- AWS Inspector needs to be enabled and configured
- When an account is being setup for vulnerability scanning & patching operations. Although AWS Inspector is enabled in all accounts, this script will establish critical configurations for optimal operations such as:
  - Assigining the correct role to all Ec2 instances
  - Scheduling weekly reports
  - Creating all required dependencies (IAM roles, S3 buckets, etc.)

It is recommended this script be ran in all AWS accounts as they are on-boarded to be patched and managed by Systems Manager. 

## Considerations
- Ensure that you have the proper permissions to run this script. It is required that the user have **Administrator** permissions. 
- Even after running this script, AWS Inspector will not be 100% in all cases. AWS Inspector does require connectivity to Ec2 instances, which either must be publicly accessible on Port 443 or be configured with the correct VPC endpoints. In either case, further configureation must be required. For Lambda functions, only those modified or invoked in the previous 90 days will be scanned.

