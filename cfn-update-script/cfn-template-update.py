#!/usr/bin/env python3

# This script is designed to automate the process of updating AWS CloudFormation templates associated with applications managed by Arpio, an AWS disaster recovery service.

# First-time Setup Instructions
# 1. Make sure you have python 3 installed.  Get it here: https://www.python.org/downloads/
# 2. Copy this script and accompanying artifacts to a folder of your choosing.
# 3. Open a Windows Command Prompt or Linux/Mac Terminal and cd to the folder you chose in step #2.
# 4. Run this command on Windows: py -m venv venv
#    or this command on Linux/Mac: python3 -m venv venv
# 5. Go run the Every-time Setup Instructions below

# Every-time Setup Instructions
# 1. Run this command on Windows: .\venv\Scripts\activate
#    or this command on Linux/Mac: . ./venv/bin/activate
# 2. Run this command: pip install -r requirements.txt
# ----------- Multi-threaded printing capability ----------

# Usage
# Invoke the script. When prompted, enter the following parameters:
# 1. Arpio Account ID (Navigate to Settings > Account in the Arpio console and copy the string following "Account ID: ")
# 2. Arpio User ID (This will be the email address you use to login to the Arpio application)
# 3. Arpio Password (The password you use to login the user ID from step 2)
# By default, the script will assume the IAM role: OrganizationAccountAccessRole for each AWS account associated with an Arpio Application.

import argparse
import json
import os
import threading
import time
from sys import exit
from getpass import getpass
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit, parse_qs, urljoin
from urllib.request import Request, urlopen, build_opener, HTTPCookieProcessor
from http.cookiejar import CookieJar
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from boto3.session import Session  # Replace 'somepackage' with the actual package name
except ImportError:
    exit("The 'boto3.session' package is not installed. Please install the AWS SDK for Python (Boto3) to continue, or run this script in an environment that has it.")

try:
    from botocore.exceptions import ClientError  # Replace 'somepackage' with the actual package name
except ImportError:
    exit("The 'botocore.exceptions' package is not installed. Please install the AWS SDK Botocore to continue, or run this script in an environment that has it.")


ARPIO_API_ROOT = os.environ.get('ARPIO_API') or 'https://api.arpio.io/api'
ARPIO_TOKEN_COOKIE = 'ArpioSession'
DEFAULT_IAM_ROLE = 'OrganizationAccountAccessRole'


# ----------- Multi-threaded printing capability ----------
_print_lock = threading.Lock()

def safe_print(*args, **kwargs):
    """Thread-safe print function that prevents output from interleaving."""
    with _print_lock:
        print(*args, **kwargs)

# ---------- HTTP Utilities with urllib ----------

cookie_jar = CookieJar()
opener = build_opener(HTTPCookieProcessor(cookie_jar))


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
        raise Exception('Expected 401 on unauthenticated GET operation')
    
    auth_url = json.loads(str(body, 'utf-8')).get('authenticateUrl')
    if not auth_url:
        raise Exception("Didn't get an authentication URL in 401 response")

    auth_url = urljoin(list_apps_url, auth_url)
    auth_body, _, _ = http_get(auth_url)
    auth_response = json.loads(auth_body)

    web_login_url = auth_response.get('loginUrl')
    if not web_login_url:
        raise Exception("No loginUrl in auth flow response")

    query_params = parse_qs(urlsplit(web_login_url).query)
    auth_token = query_params.get('authToken', [None])[0]
    if not auth_token:
        raise Exception(f"No authToken in URL: {web_login_url}")

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


def query_applications(token, arpio_account):
    url = build_arpio_url('accounts', arpio_account, 'applications')
    body, code, _ = http_get(url, headers={'Cookie': f'{ARPIO_TOKEN_COOKIE}={token}'})
    if code != 200:
        raise Exception(f'Failed to query applications: {body.decode()}')
    applications = json.loads(body)
    return [((app['sourceAwsAccountId'], app['sourceRegion']),
             (app['targetAwsAccountId'], app['targetRegion'])) for app in applications]


def needs_template_update(token, arpio_account, source_account, source_region, target_account, target_region):
    url = build_arpio_url('accounts', arpio_account, 'syncPairs',
                          source_account, source_region, target_account, target_region, 'access')
    body, code, _ = http_get(url, headers={'Cookie': f'{ARPIO_TOKEN_COOKIE}={token}'})
    if code != 200:
        raise Exception(f'Failed to query sync pair: {body.decode()}')
    info = json.loads(body)
    source_stack = None if info.get('sourceIsLatest', True) else info.get('sourceCloudFormationAccessStackName')
    target_stack = None if info.get('targetIsLatest', True) else info.get('targetCloudFormationAccessStackName')
    return source_stack, target_stack


def get_access_templates(arpio_account, prod, recovery, token):
    url = build_arpio_url('accounts', arpio_account, 'syncPairs',
                          prod[0], prod[1], recovery[0], recovery[1], 'accessTemplates')
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


def install_access_template(session, aws_account, region, template_url, stack_name):
    safe_print(f"⏳ Installing template in {aws_account}/{region}")
    cfn = session.client('cloudformation')
    try:
        cfn.update_stack(
            StackName=stack_name,
            TemplateURL=template_url,
            Capabilities=['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM']
        )
    except ClientError as ce:
        if "does not exist" in ce.response['Error']['Message']:
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
            raise Exception(f"Stack operation failed: {status}")


def process_sync_pair(app_tuple, token, arpio_account, role_name, session):
    (sourceAcc, sourceReg), (targetAcc, targetReg) = app_tuple
    try:
        source_stack, target_stack = needs_template_update(token, arpio_account, sourceAcc, sourceReg, targetAcc,
                                                           targetReg)
        if not source_stack and not target_stack:
            safe_print(f"✅ Sync pair up to date: {sourceAcc}/{sourceReg} → {targetAcc}/{targetReg}")
            return
        source_template, target_template = get_access_templates(arpio_account, (sourceAcc, sourceReg),
                                                                (targetAcc, targetReg), token)
        if source_stack:
            src_sess, _ = get_assumed_session(session, (sourceAcc, sourceReg), role_name)
            install_access_template(src_sess, sourceAcc, sourceReg, source_template, source_stack)
        if target_stack:
            tgt_sess, _ = get_assumed_session(session, (targetAcc, targetReg), role_name)
            install_access_template(tgt_sess, targetAcc, targetReg, target_template, target_stack)
        safe_print(f"✅ Updated: {sourceAcc}/{sourceReg} → {targetAcc}/{targetReg}")
    except Exception as e:
        safe_print(f"❌ Failed: {sourceAcc}/{sourceReg} → {targetAcc}/{targetReg}: {e}")

# ---------- Main Program ----------


def parse_args():
    parser = argparse.ArgumentParser(description='Update Arpio access templates across AWS sync pairs.')
    parser.add_argument('--arpio-account', '-a', help='Arpio account ID')
    parser.add_argument('--username', '-u', help='Arpio username (email)')
    parser.add_argument('--password', '-p', help='Arpio password')
    parser.add_argument('--role-name', '-r', default=DEFAULT_IAM_ROLE,
                        help=f'Role name to assume in each AWS account (default: {DEFAULT_IAM_ROLE})')
    parser.add_argument('--max-workers', '-w', type=int, default=20,
                        help='Max number of sync pairs to update in parallel (default: 5)')
    return parser.parse_args()


def main():
    args = parse_args()

    print("🛠 Arpio CloudFormation Access Template Updater\n")

    arpio_account = args.arpio_account or input("Arpio Account ID: ").strip()
    username = args.username or input("Arpio Username (email): ").strip()
    password = args.password or getpass("Arpio Password: ")
    role_name = args.role_name
    max_workers = args.max_workers

    token = get_arpio_token(arpio_account, username, password)
    session = Session()
    app_tuples = query_applications(token, arpio_account)

    # We only need maximum 1 worker per sync pair
    max_workers = min(max_workers, len(app_tuples))

    print(f"\n🔍 Found {len(app_tuples)} sync pairs. Starting parallel updates with {max_workers} workers...\n")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(process_sync_pair, t, token, arpio_account, role_name, session) for t in app_tuples]
        for _ in as_completed(futures):
            pass


if __name__ == '__main__':
    main()
