# Arpio Automation Scripts

A collection of Python scripts for automating common tasks with [Arpio](https://arpio.io), an AWS disaster recovery service.

These scripts are intended for public usage by existing Arpio.io customers. Refer to the Setup Instructions and Usage guidelines at the top of each script file. Please contact support@arpio.io with any questions.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Scripts Overview](#scripts-overview)
- [Query Audit Events](#query-audit-events)
- [Create API Key](#create-api-key)
- [Certificate Provisioning](#certificate-provisioning)
- [CloudFormation Template Update](#cloudformation-template-update)
- [Application Onboarding](#application-onboarding)

---

## Prerequisites

- Python 3.9 or higher
- AWS credentials configured (for scripts that interact with AWS)
- Arpio account with appropriate permissions

---

## Scripts Overview

| Script | Purpose | Requires venv |
|--------|---------|---------------|
| `query-audit-events.py` | Retrieve Arpio audit events | Yes |
| `create-api-key.py` | Create Arpio API keys | Yes |
| `provision_certs.py` | Automate ACM certificate provisioning | Yes |
| `create_validation_dns_entries.py` | Create DNS validation entries for certificates | Yes |
| `cfn-template-update.py` | Update CloudFormation access templates | No* |
| `onboard.py` | Bulk onboard applications from CSV | No* |

\* Can run in AWS CloudShell without modification

---

## Query Audit Events

Retrieves Arpio audit events for a specified account within a given time frame.

### Setup

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On Linux/Mac:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# Install dependencies
pip install click python-dateutil urllib3
```

### Usage

Set your API key as an environment variable:

```bash
export ARPIO_API_KEY="your-api-key-id:your-api-key-secret"
```

Basic usage:

```bash
# Query all events for an account
./query-audit-events.py <account-id>

# Query events within a time range
./query-audit-events.py <account-id> "2025-07-23" "2025-07-24"

# Query with specific timestamps (UTC)
./query-audit-events.py <account-id> "2025-07-23T19:55:10.001002Z" "2025-07-24T00:00:00Z"

# Use trace flag to see URLs being fetched
./query-audit-events.py <account-id> --trace
```

### Options

- `--api-hostname`: Override default API hostname (default: `api.arpio.io`)
- `--trace`: Print audit event query URLs to stderr

### Output

Events are printed to stdout in JSON Lines (JSONL) format, one event per line.

---

## Create API Key

Authenticates to an Arpio account and creates a non-interactive API key.

### Setup

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On Linux/Mac:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# Install dependencies
pip install click urllib3
```

### Usage

```bash
./create-api-key.py <account-id> <email>
```

You'll be prompted for your password. The script will output the API key details, including the secret (which is only displayed once).

### Options

- `--password`: Provide password via command line (not recommended for security)
- `--api-hostname`: Override default API hostname (default: `api.arpio.io`)

### Example Output

```bash
./create-api-key.py RQDLgR8ar2ipEV0VbfQLno user@example.com

Created API key (the secret is only ever displayed ONE TIME, right here):
{
  "apiKeyId": "abc123...",
  "secret": "xyz789...",
  ...
}

Example command using curl to list configured API keys:
curl -H 'X-Api-Key: abc123...:xyz789...' 'https://api.arpio.io/api/accounts/RQDLgR8ar2ipEV0VbfQLno/apiKeys'
```

---

## Certificate Provisioning

Two scripts work together to automate ACM certificate provisioning for missing certificates in Arpio applications.

### Setup

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On Linux/Mac:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Step 1: Provision Certificates (`provision_certs.py`)

Queries Arpio for missing certificate issues and requests DNS-validated certificates via ACM.

#### SSO Configuration

If your Arpio account uses SSO, you have two options:

1. Set the `auth_url` variable at the top of the script:
   ```python
   auth_url = "https://api.arpio.io/api/auth/authenticate?identityProviderId=your-idp-id"
   ```

2. Use the `--auth-url` flag when running the script

```bash
# Interactive mode (will prompt for credentials)
python3 provision_certs.py

# With parameters
python3 provision_certs.py \
  -a <arpio-account-id> \
  -u <username> \
  -p <password> \
  -o dns_entries.json

# With SSO authentication URL
python3 provision_certs.py \
  -a <arpio-account-id> \
  -u <username> \
  -p <password> \
  --auth-url "https://api.arpio.io/api/auth/authenticate?identityProviderId=your-idp-id" \
  -o dns_entries.json

# Dry run (test without making changes)
python3 provision_certs.py --dry-run
```

### Step 2: Create DNS Validation Entries (`create_validation_dns_entries.py`)

Creates the required DNS CNAME entries in Route53 for certificate validation.

```bash
# Using the output file from step 1
python3 create_validation_dns_entries.py -f dns_entries.json

# Dry run
python3 create_validation_dns_entries.py -f dns_entries.json --dry-run
```

### Options

**`provision_certs.py`:**
- `-a, --arpio-account`: Arpio account ID
- `-u, --username`: Arpio username
- `-p, --password`: Arpio password
- `-o, --outfile`: Output file for DNS entries (default: print to console)
- `-d, --dry-run`: Test mode, don't create certificates
- `--auth-url`: SSO identity provider authentication URL (format: `https://api.arpio.io/api/auth/authenticate?identityProviderId=<your-id>`)

**`create_validation_dns_entries.py`:**
- `-f, --entry-file`: Input JSON file from provision_certs.py
- `-d, --dry-run`: Test mode, don't create DNS entries

---

## CloudFormation Template Update

Updates CloudFormation access templates across all Arpio sync pairs. Can run in AWS CloudShell without setup.

### Setup (Optional)

If not using CloudShell:

```bash
# Ensure boto3 is installed
pip install boto3>=1.26.30
```

### Usage

```bash
# Using API key authentication
python3 cfn-template-update.py \
  -a <arpio-account-id> \
  --auth-type api \
  -k <api-key-id>:<api-key-secret>

# Using username/password authentication
python3 cfn-template-update.py \
  -a <arpio-account-id> \
  -t token \
  -u <username> \
  -p <password>

# Using environment variables
export ARPIO_API_KEY="<api-key-id>:<api-key-secret>"
python3 cfn-template-update.py -a <arpio-account-id> -t api
```

### Options

- `-a, --arpio-account`: Arpio account ID (required)
- `-t, --auth-type`: Authentication type: `api` or `token` (required)
- `-u, --username`: Arpio username (for token auth)
- `-p, --password`: Arpio password (for token auth)
- `-k, --api-key`: Arpio API key in format `<keyId>:<secret>` (for API auth)
- `-r, --role-name`: IAM role to assume in each account (default: `OrganizationAccountAccessRole`)
- `-w, --max-workers`: Max parallel workers (default: 20)
- `--proxy`: Enable proxy support
- `-n, --debug-network`: Enable HTTP/S network debugging

### Environment Variables

- `ARPIO_API_KEY`: API key for authentication
- `ARPIO_USERNAME`: Username for token authentication
- `ARPIO_PASSWORD`: Password for token authentication

---

## Application Onboarding

Bulk creates Arpio applications and installs CloudFormation access templates from a CSV file.

### Setup (Optional)

If not using CloudShell:

```bash
# Ensure boto3 is installed
pip install boto3>=1.26.30
```

### CSV Format

Create a CSV file with the following columns:

| Column | Description | Example | Required |
|--------|-------------|---------|----------|
| `primary_environment` | Primary AWS account/region | `123456789012/us-east-1` | Yes |
| `primary_iam_role` | IAM role in primary account | `MyProdRole` | No |
| `recovery_environment` | Recovery AWS account/region | `987654321098/us-west-2` | Yes |
| `recovery_iam_role` | IAM role in recovery account | `MyRecRole` | No |
| `application_name` | Name for the Arpio application | `TestApp` | Yes |
| `recovery_point_objective (in minutes)` | RPO in minutes | `60` | No (default: 60) |
| `notification_email` | Email for notifications | `notify@example.com` | No |
| `tag_rules` | Space-separated tag key=value pairs | `key=value another=tag` | No (default: `arpio-protected=true`) |

### Example CSV

```csv
primary_environment,primary_iam_role,recovery_environment,recovery_iam_role,application_name,recovery_point_objective (in minutes),notification_email,tag_rules
123456789012/us-east-1,MyProdRole,987654321098/us-west-2,MyRecRole,TestApp,60,notify@example.com,key=value something=else and-a-third=true
123456789012/us-east-1,,987654321098/us-west-2,,AnotherApp,30,alerts@example.com,environment=production tier=critical
```

### Usage

```bash
# Using API key authentication
python3 onboard.py \
  --csv applications.csv \
  -a <arpio-account-id> \
  -t api \
  -k <api-key-id>:<api-key-secret>

# Using username/password authentication
python3 onboard.py \
  --csv applications.csv \
  -a <arpio-account-id> \
  --auth-type token \
  -u <username> \
  -p <password>

# Using environment variables
export ARPIO_API_KEY="<api-key-id>:<api-key-secret>"
python3 onboard.py --csv applications.csv -a <arpio-account-id> --auth-type api
```

### Options

- `--csv`: Path to input CSV file (required)
- `-a, --arpio-account`: Arpio account ID (required)
- `-t, --auth-type`: Authentication type: `api` or `token` (required)
- `-u, --username`: Arpio username (for token auth)
- `-p, --password`: Arpio password (for token auth)
- `-k, --api-key`: Arpio API key in format `<keyId>:<secret>` (for API auth)
- `--proxy`: Enable proxy support
- `-n, --debug-network`: Enable HTTP/S network debugging (insecure, logs tokens)

### Environment Variables

- `ARPIO_API_KEY`: API key for authentication
- `ARPIO_USERNAME`: Username for token authentication
- `ARPIO_PASSWORD`: Password for token authentication
- `ARPIO_API`: Override API root URL (default: `https://api.arpio.io/api`)

### Process

The script runs in two phases:

1. **Application Creation**: Creates all applications in parallel
2. **Template Installation**: Installs CloudFormation access templates sequentially

---

## Security Notes

- Never commit credentials to version control
- Use environment variables or secure credential stores for sensitive data
- API key secrets are only displayed once during creation - save them securely
- The `--debug-network` flag logs sensitive information and should only be used for troubleshooting

---

## License

Copyright 2024-2025 Arpio, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

---

## Support

For issues or questions about these scripts, contact Arpio support or refer to the [Arpio documentation](https://docs.arpio.io).
