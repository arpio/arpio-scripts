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
import threading
import time
import re 
from sys import exit, version_info
from typing import List
from dataclasses import dataclass
from getpass import getpass
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit, parse_qs, urljoin
from urllib.request import Request, urlopen, build_opener, HTTPCookieProcessor, ProxyHandler, HTTPHandler, HTTPSHandler, install_opener
from http import cookiejar
from concurrent.futures import ThreadPoolExecutor, as_completed

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


def get_cookie_value(name):
    return next((cookie.value for cookie in cookie_jar if cookie.name == name), None)


def check_email(email):
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.[A-Za-z]{2,7}\b'
    # pass the regular expression
    # and the string into the fullmatch() method
    if re.fullmatch(regex, email):
        return False
    else:
        print("Invalid email address format.")
        return True


# ---------- Arpio API Functions ----------


def build_arpio_url(*path_bits):
    return '/'.join([ARPIO_API_ROOT] + list(path_bits))


def get_arpio_token(account_id, username, password):
    list_account_url = build_arpio_url(f'accounts')
    body, status, resp_headers = http_get(list_account_url)
    if status != 401:
        raise Exception(' Expected 401 on unauthenticated GET operation')
    
    auth_url = json.loads(str(body, 'utf-8')).get('authenticateUrl')
    if not auth_url:
        raise Exception(' No authentication URL in 401 response')

    auth_url = urljoin(list_account_url, auth_url)
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


def query_environments(arpio_auth_header, arpio_account:str)->List[SyncPair]:
    url = build_arpio_url('accounts', arpio_account, 'applications')
    body, code, _ = http_get(url, headers=arpio_auth_header)
    if code != 200:
        raise Exception(f'Failed to query applications: {body.decode()}')
    applications = json.loads(body)

    return [SyncPair(app['sourceAwsAccountId'], app['sourceRegion'], app['targetAwsAccountId'], 
                                                       app['targetRegion']) for app in applications]


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
def update_template(upd:TemplateUpdate,session:Session,role:str) -> None:
    try:
        assume_sess, _ = get_assumed_session(session, (upd.aws_id, upd.region), role)
        install_access_template(assume_sess, upd.aws_id, upd.region, upd.template, upd.stack)
        safe_print(f'✅ Updated environment: {upd.aws_id}/{upd.region}')            
    except Exception as e:
        safe_print(f'❌ Failed to update {upd.aws_id}/{upd.region} environment template:{e}')


# ---------- Main Program ----------




def main():
    parser = argparse.ArgumentParser(description='Update Arpio access templates across AWS sync pairs.')
    parser.add_argument('-a', '--arpio-account', help='Arpio Account ID', required=True)
    parser.add_argument('-t', '--auth-type', help='Form of authentication between User/Pass \"Token\" and \"API\" Key.  \
                        API keys may be stored as an environment variable under \"ARPIO_API_KEY\", or provided as an optional argument. \
                        If using Token authentication, provide the username and password arguments to the script. \
                        Both username and password can be stored as environmental \
                        variables under \"ARPIO_USERNAME\" and \"ARPIO_PASSWORD\"',
                        required=True, choices=['api','token'], default='token')
    parser.add_argument('-u', '--username', help='Arpio Username')
    parser.add_argument('-p', '--password', help='Arpio Password')
    parser.add_argument('-k', '--api-key', help='Arpio API key in the form \"<apiKeyID>:<secret>\"')
    parser.add_argument('-r', '--role-name', default=DEFAULT_IAM_ROLE,
                        help=f'Role name to assume in each AWS account (default: {DEFAULT_IAM_ROLE})')
    parser.add_argument('-s', '--stack-name', default=DEFAULT_STACK_NAME,
                        help=f'CloudFormation Stack name to create if it doesn\'t exist. (default: {DEFAULT_STACK_NAME})')
    parser.add_argument('-w', '--max-workers', type=int, default=20,
                        help='Max number of sync pairs to update in parallel (default: 20)')
    parser.add_argument('--proxy', help='Flag to indicate the usage of a proxy server. Proxy server must be kept in standard environment variables for autodetection to work.', action='store_true', default=False)
    parser.add_argument('-n', '--debug-network', help='Flag to enable HTTP/S Network Debugging flagging', action='store_true', default=False)
    args = parser.parse_args()

    setup_handler(args.debug_network, args.proxy)


    print('🛠 Arpio CloudFormation Access Template Updater\n')
    arpio_account = args.arpio_account or input('Arpio Account ID: ').strip()

    if args.auth_type == 'api':
        if args.auth_type == 'api' and args.api_key is None and os.environ.get('ARPIO_API_KEY') is None:
            print('--auth_type api requires --api_key to be set, manually enter API key.')
        api_key = args.api_key or os.environ.get('ARPIO_API_KEY') or getpass('Arpio API key: ')
        if api_key is None:
            parser.error('API key not found')
            exit(1)
        arpio_auth_header = {'X-Api-Key' : api_key}
    elif args.auth_type == 'token':
        try:
            username = args.username or os.getenv("ARPIO_USERNAME") or input(f'Arpio username (email address): ')
            if check_email(username):
                exit(1)
            password = (args.password or os.getenv("ARPIO_PASSWORD")) or getpass('Arpio password: ')
            token = get_arpio_token(arpio_account, username, password)
            arpio_auth_header = {ARPIO_TOKEN_COOKIE : token}

        except Exception as e:
            print(f"{e}")
            exit(1)
    else:
        print(f'Missing arguments for authentication type. Please check your arguments and try again.')    
        exit(1)    

    check_version()

    role_name = args.role_name
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
        print(f'\n❌ Exception Caught: {e} \n')


    max_workers = min(max_workers, len(template_updates)) ##recalculate thread pool for non-duplicate sync pair tuples 

    print(f'\n🔍 Found {len(template_updates)} templates to upgrade. Starting parallel updates with {max_workers} workers...\n')
    if max_workers == 0:
        print(f'\n✅ No templates to upgrade, exiting...\n')
        exit(0)

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(update_template, template, session, role_name) for template in template_updates]

            for _ in as_completed(futures):
                pass
    except Exception as e:
        print(f'\n❌ Exception Caught: {e} \n')



if __name__ == '__main__':
    main()

