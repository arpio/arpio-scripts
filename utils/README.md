# Arpio Utility Scripts

Collection of utility scripts for working with AWS and Arpio infrastructure.

## Prerequisites

Install required dependencies:

```bash
pip install -r requirements.txt
```

## Scripts

### export_iam_role_policies.py

Export all IAM role policies (both attached managed policies and inline policies) to a JSON file.

**Usage:**

```bash
# Using role name
python export_iam_role_policies.py ArpioPrimaryDelegate

# Using role ARN
python export_iam_role_policies.py arn:aws:iam::123456789012:role/ArpioPrimaryDelegate

# With AWS profile
python export_iam_role_policies.py ArpioRecoveryAccess --profile my-profile

# Custom output filename
python export_iam_role_policies.py ArpioRecoveryAccess --output custom-name.json
```

**Output:**

Creates a JSON file containing:
- Role name and ARN
- All attached managed policies (AWS and customer managed)
- All inline policies
- Full policy documents for each policy

**Example:**

```bash
python export_iam_role_policies.py ArpioPrimaryAccess-ABCmukP1fRsL19GRT123Ac-us-east-1
```

Output: `ArpioPrimaryAccess.json`

---

### sts_endpoint.py

Diagnostic utility to illustrate which STS endpoints AWS SDK uses with different `AWS_STS_REGIONAL_ENDPOINTS` settings.

**Usage:**

```bash
python sts_endpoint.py
```

**What it does:**

Tests STS endpoint resolution across different regions with three configurations:
- `AWS_STS_REGIONAL_ENDPOINTS=legacy` - Uses global STS endpoint (sts.amazonaws.com)
- `AWS_STS_REGIONAL_ENDPOINTS=regional` - Uses regional STS endpoints
- Unset - Uses default behavior

Tests regions:
- `ap-south-2` (opt-in region)
- `us-east-1` (original region)
- `us-east-2`
- `ap-southeast-1`
- No region specified (default)

Also checks for `sts_regional_endpoints` settings in AWS config files.

**Example output:**

```
Setting: legacy
Boto3 version: 1.26.0
Botocore version: 1.29.0

Testing different regions:
  ap-south-2: https://sts.amazonaws.com
  us-east-1: https://sts.amazonaws.com
  us-east-2: https://sts.amazonaws.com
  ...
```


