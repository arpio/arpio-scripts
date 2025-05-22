#!/usr/bin/env python3
# Copyright 2025 Arpio, Inc.

# This script is designed to automate the process of updating AWS CloudFormation templates associated with applications managed by Arpio, an AWS disaster recovery service.

# First-time Setup Instructions
# 1. Make sure you have python >= 3.12 installed.  Get it here: https://www.python.org/downloads/
# 2. Make sure you have boto3 >=1.26.30 installed. See instructions here: https://boto3.amazonaws.com/v1/documentation/api/latest/guide/quickstart.html/
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
import threading
import time
from sys import exit, version_info
from typing import List
from dataclasses import dataclass
from getpass import getpass
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit, parse_qs, urljoin
from urllib.request import Request, urlopen, build_opener, HTTPCookieProcessor
from http.cookiejar import CookieJar
from concurrent.futures import ThreadPoolExecutor, as_completed

ARPIO_API_ROOT = os.environ.get('ARPIO_API') or 'https://api.arpio.io/api'
ARPIO_TOKEN_COOKIE = 'ArpioSession'
DEFAULT_IAM_ROLE = 'OrganizationAccountAccessRole'


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
    expect_minor = 12
    current_version = str(version_info[0])+"."+str(version_info[1])+"."+str(version_info[2])
    print("INFO: Script developed and tested with Python " + str(expect_major) + "." + str(expect_minor))
    if (version_info[0], version_info[1]) < (expect_major, expect_minor):
        print("Current Python version is unsupported: Python " + current_version)

# ----------- Boto3 import check ----------   
try:
    from boto3.session import Session 
    from botocore.exceptions import ClientError     
except ImportError:
    safe_print('The "boto3" package is not installed. Please install the AWS SDK for Python (Boto3) to continue, or run this script in an environment that has it.')
    exit()



# ---------- HTTP Utilities with urllib ----------
check_version()
cookie_jar = CookieJar()
opener = build_opener(HTTPCookieProcessor(cookie_jar))

#dataclass containing the 
@dataclass(frozen=True)
class TemplateUpdate:
    aws_id:str
    region:str
    template:str
    stack:str

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


def get_cookie_value(name):
    for cookie in cookie_jar:
        if cookie.name == name:
            return cookie.value
    return None

# ---------- Arpio API Functions ----------


def build_arpio_url(*path_bits):
    return '/'.join([ARPIO_API_ROOT] + list(path_bits))


def get_arpio_token(account_id, username, password):
    list_apps_url = build_arpio_url(f'accounts/{account_id}/applications')
    body, status, resp_headers = http_get(list_apps_url)
    if status != 401:
        raise Exception(' Expected 401 on unauthenticated GET operation')
    
    auth_url = json.loads(str(body, 'utf-8')).get('authenticateUrl')
    if not auth_url:
        raise Exception(' No authentication URL in 401 response')

    auth_url = urljoin(list_apps_url, auth_url)
    auth_body, _, _ = http_get(auth_url)
    auth_response = json.loads(auth_body)

    web_login_url = auth_response.get('loginUrl')
    if not web_login_url:
        raise Exception('No loginUrl in auth flow response')

    query_params = parse_qs(urlsplit(web_login_url).query)
    auth_token = query_params.get('authToken', [None])[0]
    if not auth_token:
        raise Exception(f'No authToken in URL: {web_login_url}')

    login_url = f'{urlsplit(auth_url).scheme}://{urlsplit(auth_url).netloc}/api/users/login'
    body, code, _ = http_post(login_url, {'email': username, 'password': password})
    if code != 200:
        raise Exception(f'Login failed: {body.decode()}')

    native_auth_token = json.loads(body).get('nativeAuthToken')
    if not native_auth_token:
        raise Exception('Missing nativeAuthToken')

    native_acs_url = f'{urlsplit(auth_url).scheme}://{urlsplit(auth_url).netloc}/api/auth/nativeAcs'
    body, code, _ = http_post(native_acs_url, {
        'authToken': auth_token,
        'nativeAuthToken': native_auth_token
    })
    if code != 200:
        raise Exception(f'Native ACS login failed: {body.decode()}')

    token = get_cookie_value(ARPIO_TOKEN_COOKIE)
    if not token:
        raise Exception('Failed to retrieve Arpio session token')
    return token


def query_environments(token:str, arpio_account:str)->List[SyncPair]:
    url = build_arpio_url('accounts', arpio_account, 'applications')
    body, code, _ = http_get(url, headers={'Cookie': f'{ARPIO_TOKEN_COOKIE}={token}'})
    if code != 200:
        raise Exception(f'Failed to query applications: {body.decode()}')
    applications = json.loads(body)

    return [SyncPair(app['sourceAwsAccountId'], app['sourceRegion'], app['targetAwsAccountId'], 
                                                       app['targetRegion']) for app in applications]


def needs_template_update(token, arpio_account, sync_pair:SyncPair) -> List[TemplateUpdate]:
    url = build_arpio_url('accounts', arpio_account, 'syncPairs',
                          sync_pair.src_id, sync_pair.src_reg, sync_pair.tgt_id, sync_pair.tgt_reg, 'access')
    body, code, _ = http_get(url, headers={'Cookie': f'{ARPIO_TOKEN_COOKIE}={token}'})
    if code != 200:
        raise Exception(f'Failed to query sync pair: {body.decode()}')
    info = json.loads(body)

    source_stack = None if info.get('sourceIsLatest', True) and info.get('sourceConfigValid') else info.get('sourceCloudFormationAccessStackName')
    target_stack = None if info.get('targetIsLatest', True) and info.get('targetConfigValid') else info.get('targetCloudFormationAccessStackName')
    updates=[]

    try:
        if source_stack or target_stack:
            source_template, target_template = get_access_templates(arpio_account, sync_pair, token)
    except Exception as e:
        safe_print(f'❌ Unable to check environment templates:  {sync_pair.src_id}/{sync_pair.src_reg} & {sync_pair.tgt_id}/{sync_pair.tgt_reg} - Exception: {e}')
        return
    
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


def get_access_templates(arpio_account, sync_pair:SyncPair, token):
    url = build_arpio_url('accounts', arpio_account, 'syncPairs',
                          sync_pair.src_id, sync_pair.src_reg, sync_pair.tgt_id, sync_pair.tgt_reg, 'accessTemplates')
    body, code, _ = http_get(url, headers={'Cookie': f'{ARPIO_TOKEN_COOKIE}={token}'})
    if code != 200:
        raise Exception(f'Failed to get access templates: {body.decode()}')
    templates = json.loads(body)

    return templates['sourceTemplateS3Url'], templates['targetTemplateS3Url']


def get_assumed_session(boto_session, environment, role):
    region_name = environment[1]
    sts = boto_session.client('sts', region_name=region_name)
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
def update_template(upd:TemplateUpdate,session:Session,role:str) -> None:
    try:
        assume_sess, _ = get_assumed_session(session, (upd.aws_id, upd.region), role)
        install_access_template(assume_sess, upd.aws_id, upd.region, upd.template, upd.stack)
        safe_print(f'✅ Updated environment: {upd.aws_id}/{upd.region}')            
    except Exception as e:
        safe_print(f'❌ Failed to update {upd.aws_id}/{upd.region} environment template:{e}')


# ---------- Main Program ----------


def parse_args():
    parser = argparse.ArgumentParser(description='Update Arpio access templates across AWS sync pairs.')
    parser.add_argument('--arpio-account', '-a', help='Arpio account ID')
    parser.add_argument('--username', '-u', help='Arpio username (email)')
    parser.add_argument('--password', '-p', help='Arpio password')
    parser.add_argument('--role-name', '-r', default=DEFAULT_IAM_ROLE,
                        help=f'Role name to assume in each AWS account (default: {DEFAULT_IAM_ROLE})')
    parser.add_argument('--max-workers', '-w', type=int, default=20,
                        help='Max number of sync pairs to update in parallel (default: 20)')
    return parser.parse_args()


def main():
    args = parse_args()

    print('🛠 Arpio CloudFormation Access Template Updater\n')
    arpio_account = args.arpio_account or input('Arpio Account ID: ').strip()
    username = args.username or input('Arpio Username (email): ').strip()
    password = args.password or getpass('Arpio Password: ')
    
    check_version()

    role_name = args.role_name
    safe_print('Using '+role_name+' for AWS IAM Role\n')

    max_workers = args.max_workers

    token = get_arpio_token(arpio_account, username, password)
    session = Session()

    unique_pairs = set(query_environments(token, arpio_account))
    template_updates = set()
    
    max_workers = min(max_workers, len(unique_pairs)) ## calculate thread pool for unique syncpairs
    print(f'\n🔍 Found {len(unique_pairs)} unique sync pairs. Starting parallel template update checks with {max_workers} workers...\n')
    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(needs_template_update, token, arpio_account, sync_pair) for sync_pair in unique_pairs]

            for f in as_completed(futures):
                template_updates.update(f.result())
    except Exception as e:
        print(f'\n❌ Exception Caught: {e} \n')


    max_workers = min(max_workers, len(template_updates)) ##recalculate thread pool for non-duplicate sync pair tuples 

    print(f'\n🔍 Found {len(template_updates)} templates to upgrade. Starting parallel updates with {max_workers} workers...\n')
    if max_workers == 0:
        print(f'\n✅ No templates to upgrade, exiting...\n')
        exit()

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(update_template, template, session, role_name) for template in template_updates]

            for _ in as_completed(futures):
                pass
    except Exception as e:
        print(f'\n❌ Exception Caught: {e} \n')



if __name__ == '__main__':
    main()

