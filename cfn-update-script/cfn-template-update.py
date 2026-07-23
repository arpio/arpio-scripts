#!/usr/bin/env python3
# Copyright 2025 Arpio, Inc.

# This script is designed to automate the process of updating AWS CloudFormation templates associated with applications managed by Arpio, an AWS disaster recovery service.

# First-time Setup Instructions
# --- This script can be run in AWS Cloud Shell without modification to the shell environment ---
# 1. Make sure you have python >= 3.9 installed.  Get it here: https://www.python.org/downloads
# 2. Make sure you have boto3 >=1.26.30 installed. See instructions here: https://boto3.amazonaws.com/v1/documentation/api/latest/guide/quickstart.html
# 2. Copy this script and accompanying artifacts to a folder of your choosing.
# 3. You will need to be logged in to Amazon Web Services and have sufficient permissions to assume the OrganizationAccountAccessRole 
# or a role that can assume the necessary permissions to update CloudFormationTemplates across multiple accounts

# Usage
# Invoke the script. When prompted, enter the following parameters:
# 1. Arpio Account ID (Navigate to Settings > Account in the Arpio console and copy the string following 'Account ID: ')
# 2. Arpio User ID (This will be the email address you use to login to the Arpio application)
# 3. Arpio Password (The password you use to login the user ID from step 2)
# By default, the script will assume the IAM role: OrganizationAccountAccessRole for each AWS account associated with an Arpio Application.

import argparse
import json
import os
import sys
import subprocess
import threading
import time
import re
from sys import exit, version_info
from typing import List, Optional
from dataclasses import dataclass
from getpass import getpass
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit, parse_qs, urljoin
from urllib.request import Request, urlopen, build_opener, HTTPCookieProcessor, ProxyHandler, HTTPHandler, HTTPSHandler, install_opener
from http import cookiejar
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import the shared Arpio authentication helpers from the sibling utils/ directory.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'utils'))
import arpio_auth

ARPIO_API_ROOT = os.environ.get('ARPIO_API') or 'https://api.arpio.io/api'
ARPIO_TOKEN_COOKIE = 'ArpioSession'
DEFAULT_IAM_ROLE = 'OrganizationAccountAccessRole'
DEFAULT_STACK_NAME = 'arpio-access'
os.environ['AWS_STS_REGIONAL_ENDPOINTS'] = 'regional'
opener = build_opener()
cookie_jar = cookiejar.CookieJar()
cookie_handler = HTTPCookieProcessor(cookie_jar)

# ----------- Boto3 import check ----------   
try:
    from boto3.session import Session 
    from botocore.exceptions import ClientError     
except ImportError:
    print('The "boto3" package is not installed. Please install the AWS SDK for Python (Boto3) to continue, or run this script in an environment that has it.')
    exit(1)

# ----------- Multi-threaded printing capability ----------
### Thread-safe print function that prevents output from interleaving.
_print_lock = threading.Lock()

def safe_print(*args, **kwargs):
    with _print_lock:
        print(*args, **kwargs)

# ----------- Version Chec ----------
### Checks current Python version and warns on older than supported.
def check_version():
    # Checking Python version:
    expect_major = 3
    expect_minor = 9
    current_version = str(version_info[0])+"."+str(version_info[1])+"."+str(version_info[2])
    print("INFO: Script developed and tested with Python " + str(expect_major) + "." + str(expect_minor))
    if (version_info[0], version_info[1]) < (expect_major, expect_minor):
        print("Current Python version is older than expected: Python " + current_version)

check_version()

# ---------- HTTP Utilities with urllib ----------

def setup_handler(debug_network, proxy):
    global opener
    global cookie_jar

    http_handler = HTTPHandler(debuglevel=1)
    https_handler = HTTPSHandler(debuglevel=1)
   
    if proxy and debug_network:
        opener = build_opener(
            ProxyHandler(),
            cookie_handler,
            http_handler, 
            https_handler
        ) 
    elif debug_network:
        opener = build_opener(
            cookie_handler,
            http_handler, 
            https_handler
        ) 
    # Create Opener
    elif proxy:
        opener = build_opener(
            ProxyHandler(),
            cookie_handler
        )
    else:
        opener = build_opener(
            cookie_handler
        )
    install_opener(opener)
    return

# Dataclass containing the template information
@dataclass(frozen=True)
class TemplateUpdate:
    aws_id:str
    region:str
    template:str
    stack:str

# Dataclass containing the Sync Pair information
@dataclass(frozen=True)
class SyncPair:
    src_id:str
    src_reg:str
    tgt_id:str
    tgt_reg:str

def http_get(url, headers=None):
    req = Request(url, headers=headers or {}, method='GET')
    try:
        with opener.open(req) as response:
            return response.read(), response.getcode(), response.headers
    except HTTPError as e:
        return e.read(), e.code, e.headers


def http_post(url, data=None, headers=None):
    json_data = json.dumps(data or {}).encode('utf-8')
    req = Request(url, data=json_data, headers=headers or {
        'Content-Type': 'application/json'
    }, method='POST')
    with opener.open(req) as response:
        return response.read(), response.getcode(), response.headers


# ---------- Arpio API Functions ----------


def build_arpio_url(*path_bits):
    return '/'.join([ARPIO_API_ROOT] + list(path_bits))


def query_environments(arpio_auth_header, arpio_account:str)->List[SyncPair]:
    url = build_arpio_url('accounts', arpio_account, 'applications')
    body, code, _ = http_get(url, headers=arpio_auth_header)
    if code != 200:
        raise Exception(f'Failed to query applications: {body.decode()}')
    applications = json.loads(body)

    # Skip applications where sourceAwsAccountId is null - These are Azure applications - TODO: we should handle these.
    return [SyncPair(app['sourceAwsAccountId'], app['sourceRegion'], app['targetAwsAccountId'], 
                     app['targetRegion']) for app in applications if app['sourceAwsAccountId'] is not None]


def needs_template_update(arpio_auth_header, arpio_account, sync_pair:SyncPair, stack_name: str) -> List[TemplateUpdate]:
    url = build_arpio_url('accounts', arpio_account, 'syncPairs',
                          sync_pair.src_id, sync_pair.src_reg, sync_pair.tgt_id, sync_pair.tgt_reg, 'access')
    body, code, _ = http_get(url, headers=arpio_auth_header)
    if code != 200:
        raise Exception(f'Failed to query sync pair: {body.decode()}')
    info = json.loads(body)

    source_stack = None if info.get('sourceIsLatest') and info.get('sourceConfigValid') else info.get('sourceCloudFormationAccessStackName') or stack_name
    target_stack = None if info.get('targetIsLatest') and info.get('targetConfigValid') else info.get('targetCloudFormationAccessStackName') or stack_name
    updates=[]

    try:
        if source_stack or target_stack:
            source_template, target_template = get_access_templates(arpio_account, sync_pair, arpio_auth_header)
    except Exception as e:
        safe_print(f'❌ Unable to check environment templates:  {sync_pair.src_id}/{sync_pair.src_reg} & {sync_pair.tgt_id}/{sync_pair.tgt_reg} - Exception: {e}')
        return updates
    
    if source_stack:
        updates.append(TemplateUpdate(sync_pair.src_id, sync_pair.src_reg, source_template, source_stack))
        safe_print(f'✅ Source environment template requires update: {sync_pair.src_id}/{sync_pair.src_reg}')
    else:
        safe_print(f'✅ Source environment template up to date: {sync_pair.src_id}/{sync_pair.src_reg}')

    if target_stack:
        updates.append(TemplateUpdate(sync_pair.tgt_id, sync_pair.tgt_reg, target_template, target_stack))
        safe_print(f'✅ Target environment template requires update: {sync_pair.tgt_id}/{sync_pair.tgt_reg}')
    else:
        safe_print(f'✅ Target environment template up to date: {sync_pair.tgt_id}/{sync_pair.tgt_reg}')
    
    return updates


def get_access_templates(arpio_account, sync_pair:SyncPair, arpio_auth_header):
    url = build_arpio_url('accounts', arpio_account, 'syncPairs',
                          sync_pair.src_id, sync_pair.src_reg, sync_pair.tgt_id, sync_pair.tgt_reg, 'accessTemplates')
    body, code, _ = http_get(url, headers=arpio_auth_header)
    if code != 200:
        raise Exception(f'Failed to get access templates: {body.decode()}')
    templates = json.loads(body)

    return templates['sourceTemplateS3Url'], templates['targetTemplateS3Url']


# ---------- SSO Authentication ----------

SSO_SESSION_DURATION = '3600'

# Cache for SSO credentials: key is account_id -> dict with credentials
_sso_credentials_cache = {}
_sso_cache_lock = threading.Lock()


def authenticate_sso(role_arn: str, idp_id: str, sp_id: str, account_id: str) -> dict:
    """Authenticate via Google SSO using gsts and return credentials dict."""
    cmd = [
        'gsts',
        '--aws-role-arn', role_arn,
        '--aws-region', 'us-east-1',  # Region doesn't matter for auth, credentials work in any region
        '--idp-id', idp_id,
        '--sp-id', sp_id,
        '--aws-session-duration', SSO_SESSION_DURATION,
        '--aws-profile', f'arpio-sso-{account_id}',  # Use unique profile per account to avoid cache conflicts
        '-o', 'json',
    ]

    safe_print(f'🔐 Authenticating via SSO for {role_arn}...')
    proc = subprocess.run(cmd, capture_output=True)

    if proc.returncode != 0:
        stderr = proc.stderr.decode() if proc.stderr else ''
        raise Exception(f'SSO authentication failed for {role_arn}: {stderr}')

    if not proc.stdout:
        raise Exception(f'SSO authentication returned no credentials for {role_arn}')

    output = json.loads(proc.stdout)

    return {
        'AccessKeyId': output['AccessKeyId'],
        'SecretAccessKey': output['SecretAccessKey'],
        'SessionToken': output['SessionToken'],
    }


def get_sso_session(account_id: str, region: str, sso_config: Optional[dict], idp_id: str, sp_id: str) -> Session:
    """Get or create an SSO session for the given account and region."""
    with _sso_cache_lock:
        credentials = _sso_credentials_cache.get(account_id)

    if not credentials:
        role_name = sso_config.get(account_id)
        if not role_name:
            raise Exception(f'No SSO role mapping found for account {account_id} in config')

        role_arn = f'arn:aws:iam::{account_id}:role/{role_name}'
        credentials = authenticate_sso(role_arn, idp_id, sp_id, account_id)

        with _sso_cache_lock:
            _sso_credentials_cache[account_id] = credentials

    return Session(
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name=region
    )


def pre_authenticate_sso(template_updates, sso_config: Optional[dict], idp_id: str, sp_id: str):
    """Pre-authenticate all unique accounts before parallel updates."""
    unique_accounts = set(upd.aws_id for upd in template_updates)

    safe_print(f'\n🔐 Pre-authenticating {len(unique_accounts)} unique accounts via SSO...\n')

    for account_id in unique_accounts:
        try:
            role_name = sso_config.get(account_id)
            if not role_name:
                safe_print(f'⚠️ No SSO role mapping for account {account_id} in config, skipping')
                continue
            role_arn = f'arn:aws:iam::{account_id}:role/{role_name}'

            with _sso_cache_lock:
                if account_id not in _sso_credentials_cache:
                    credentials = authenticate_sso(role_arn, idp_id, sp_id, account_id)
                    _sso_credentials_cache[account_id] = credentials

            safe_print(f'✅ SSO authenticated: {account_id}')
        except Exception as e:
            safe_print(f'❌ SSO authentication failed for {account_id}: {e}')
            raise


def get_assumed_session(boto_session, environment, role):
    region_name = environment[1]
    sts = boto_session.client('sts')
    role_arn = f'arn:aws:iam::{environment[0]}:role/{role}'
    assumed = sts.assume_role(RoleArn=role_arn, RoleSessionName='arpio_provisioning')
    return Session(
        aws_access_key_id=assumed['Credentials']['AccessKeyId'],
        aws_secret_access_key=assumed['Credentials']['SecretAccessKey'],
        aws_session_token=assumed['Credentials']['SessionToken'],
        region_name=region_name
    ), assumed['AssumedRoleUser']['Arn']

# Installs access template to AWS account-region pair provided
def install_access_template(session, aws_account, region, template_url, stack_name):
    safe_print(f'⏳ Installing template in {aws_account}/{region}')
    cfn = session.client('cloudformation')
    try:
        cfn.update_stack(
            StackName=stack_name,
            TemplateURL=template_url,
            Capabilities=['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM']
        )
    except ClientError as ce:
        if 'does not exist' in ce.response['Error']['Message']:
            cfn.create_stack(
                StackName=stack_name,
                TemplateURL=template_url,
                Capabilities=['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM']
            )
        else:
            raise

    while True:
        time.sleep(5)
        stack_details = cfn.describe_stacks(StackName=stack_name)['Stacks'][0]
        status = stack_details['StackStatus']
        if status in {'CREATE_COMPLETE', 'UPDATE_COMPLETE'}:
            break
        elif 'FAILED' in status or 'ROLLBACK' in status:
            raise Exception(f'Stack operation failed: {status}')

##does process sync pair action
def update_template(upd:TemplateUpdate, session:Session, role:str, aws_auth:str='role', sso_config:Optional[dict]=None, idp_id:str=None, sp_id:str=None) -> None:
    try:
        if aws_auth == 'sso':
            target_session = get_sso_session(upd.aws_id, upd.region, sso_config, idp_id, sp_id)
        else:
            target_session, _ = get_assumed_session(session, (upd.aws_id, upd.region), role)
        install_access_template(target_session, upd.aws_id, upd.region, upd.template, upd.stack)
        safe_print(f'✅ Updated environment: {upd.aws_id}/{upd.region}')
    except Exception as e:
        safe_print(f'❌ Failed to update {upd.aws_id}/{upd.region} environment template:{e}')


# ---------- Main Program ----------




def main():
    parser = argparse.ArgumentParser(description='Update Arpio access templates across AWS sync pairs.')
    arpio_auth.add_arpio_auth_args(parser)
    parser.add_argument('-r', '--role-name', default=DEFAULT_IAM_ROLE,
                        help=f'Role name to assume in each AWS account (default: {DEFAULT_IAM_ROLE})')
    parser.add_argument('-s', '--stack-name', default=DEFAULT_STACK_NAME,
                        help=f'CloudFormation Stack name to create if it doesn\'t exist. (default: {DEFAULT_STACK_NAME})')
    parser.add_argument('-w', '--max-workers', type=int, default=20,
                        help='Max number of sync pairs to update in parallel (default: 20)')
    parser.add_argument('--proxy', help='Flag to indicate the usage of a proxy server. Proxy server must be kept in standard environment variables for autodetection to work.', action='store_true', default=False)
    parser.add_argument('-n', '--debug-network', help='Flag to enable HTTP/S Network Debugging flagging', action='store_true', default=False)
    parser.add_argument('--aws-auth', choices=['role', 'sso'], default='role',
                        help='AWS authentication method: "role" (assume role from current session) or "sso" (Google SSO)')
    parser.add_argument('--sso-config',
                        help='Path to JSON file mapping AWS account IDs to IAM role names for SSO authentication')
    parser.add_argument('--idp-id',
                        help='Google Identity Provider ID for SSO authentication (required for SSO)')
    parser.add_argument('--sp-id',
                        help='Google Service Provider ID for SSO authentication (required for SSO)')
    args = parser.parse_args()

    setup_handler(args.debug_network, args.proxy)


    print('🛠 Arpio CloudFormation Access Template Updater\n')
    arpio_account = args.arpio_account

    try:
        arpio_auth_header = arpio_auth.resolve_auth_header(
            args, proxy=args.proxy, debug_network=args.debug_network)
    except Exception as e:
        print(f"{e}")
        exit(1)

    check_version()

    # Load SSO config if using SSO authentication
    sso_config = None
    idp_id = args.idp_id
    sp_id = args.sp_id
    role_name = args.role_name
    aws_auth = args.aws_auth

    if aws_auth == 'sso':
        if not args.sso_config:
            print('❌ --sso-config is required when using --aws-auth sso')
            exit(1)
        if not idp_id or not sp_id:
            print('❌ --idp-id and --sp-id are required when using --aws-auth sso')
            exit(1)
        try:
            with open(args.sso_config, 'r') as f:
                sso_config = json.load(f)
            safe_print(f'✅ Loaded SSO config with {len(sso_config)} account mappings')
            safe_print('Using Google SSO for AWS authentication\n')
        except FileNotFoundError:
            print(f'❌ SSO config file not found: {args.sso_config}')
            exit(1)
        except json.JSONDecodeError as e:
            print(f'❌ Invalid JSON in SSO config file: {e}')
            exit(1)
    else:
        safe_print('Using '+role_name+' for AWS IAM Role\n')

    max_workers = args.max_workers

    session = Session()

    unique_pairs = set(query_environments(arpio_auth_header, arpio_account))
    template_updates = set()
    
    max_workers = min(max_workers, len(unique_pairs)) ## calculate thread pool for unique syncpairs
    print(f'\n🔍 Found {len(unique_pairs)} unique sync pairs. Starting parallel template update checks with {max_workers} workers...\n')
    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(needs_template_update, arpio_auth_header, arpio_account, sync_pair, args.stack_name) for sync_pair in unique_pairs]

            for f in as_completed(futures):
                template_updates.update(f.result())
    except Exception as e:
        print(f'\n❌ Exception Caught during template updates: {e} \n')


    # Filter out accounts with no SSO role mapping before updating
    if aws_auth == 'sso':
        skipped = {upd for upd in template_updates if upd.aws_id not in sso_config}
        for upd in skipped:
            safe_print(f'⚠️ Skipping {upd.aws_id}/{upd.region} — no SSO role mapping in config')
        template_updates -= skipped

    max_workers = min(max_workers, len(template_updates)) ##recalculate thread pool for non-duplicate sync pair tuples

    print(f'\n🔍 Found {len(template_updates)} templates to upgrade. Starting parallel updates with {max_workers} workers...\n')
    if max_workers == 0:
        print(f'\n✅ No templates to upgrade, exiting...\n')
        exit(0)

    # Pre-authenticate all accounts via SSO before parallel updates
    if aws_auth == 'sso':
        try:
            pre_authenticate_sso(template_updates, sso_config, idp_id, sp_id)
        except Exception as e:
            print(f'\n❌ SSO pre-authentication failed: {e}')
            exit(1)

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(update_template, template, session, role_name, aws_auth, sso_config, idp_id, sp_id) for template in template_updates]

            for _ in as_completed(futures):
                pass
    except Exception as e:
        print(f'\n❌ Exception Caught during authentication: {e} \n')



if __name__ == '__main__':
    main()

