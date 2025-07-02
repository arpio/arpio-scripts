#!/usr/bin/env python3
# Copyright 2025 Arpio, Inc.

# This script is designed to automate the process of creating Arpio Applications and their accompanying AWS CloudFormation templates.

# First-time Setup Instructions
# 1. Make sure you have python >= 3.12 installed.  Get it here: https://www.python.org/downloads/
# 2. Make sure you have boto3 >=1.26.30 installed. See instructions here: https://boto3.amazonaws.com/v1/documentation/api/latest/guide/quickstart.html/
# 2. Copy this script and accompanying artifacts to a folder of your choosing.
# 3. You will need to be logged in to Amazon Web Services and have sufficient permissions to assume the OrganizationAccountAccessRole 
# or a role that can assume the necessary permissions to update CloudFormationTemplates across multiple accounts

# Usage
# Invoke the script, with the location of the CSV and the . When prompted, enter the following parameters:
# 1. Arpio Account ID (Navigate to Settings > Account in the Arpio console and copy the string following 'Account ID: ')
# 2. Arpio User ID (This will be the email address you use to login to the Arpio application)
# 3. Arpio Password (The password you use to login the user ID from step 2)
# By default, the script will assume the IAM role: OrganizationAccountAccessRole for each AWS account associated with an Arpio Application.

# csv format
# Header Columns: primary_environment,primary_iam_role,recovery_environment,recovery_iam_role,arpio_account,username,application_name,recovery_point_objective (in minutes),notification_email, tag_rules
# Examples: 123456789012/us-east-1,MyProdRole,987654321098/us-west-2,MyRecRole,arpioaccountstring,example@example.com,TestApp,60,notify@example.com, key=value something=else and-a-third=true


import json
import time
import os
import csv
import sys
import getpass
import argparse
from urllib.parse import urlsplit, parse_qs, urljoin
from urllib.request import Request, build_opener, HTTPCookieProcessor
from urllib.error import HTTPError
from concurrent.futures import ThreadPoolExecutor, as_completed
from http import cookiejar

# ----------- Boto3 import check ----------   
try:
    from boto3.session import Session 
    from botocore.exceptions import ClientError     
except ImportError:
    print('The "boto3" package is not installed. Please install the AWS SDK for Python (Boto3) to continue, or run this script in an environment that has it.')
    exit()

# ----------- Version Check ----------
### Checks current Python version and warns on older than supported.
def check_version():
    # Checking Python version:
    expect_major = 3
    expect_minor = 12
    current_version = str(sys.version_info[0])+"."+str(sys.version_info[1])+"."+str(sys.version_info[2])
    print("INFO: Script developed and tested with Python " + str(expect_major) + "." + str(expect_minor))
    if (sys.version_info[0], sys.version_info[1]) < (expect_major, expect_minor):
        print("Current Python version is unsupported: Python " + current_version)    
    
# Setup cookie jar and opener
cookie_jar = cookiejar.CookieJar()
opener = build_opener(HTTPCookieProcessor(cookie_jar))

# Declare globals
ARPIO_API_ROOT = os.environ.get('ARPIO_API') or 'https://api.arpio.io/api'

DEFAULT_ARPIO_ACCOUNT = 'arpio-account-id'
DEFAULT_ARPIO_USER = 'arpio-user-email'
DEFAULT_NOTIFICATION_ADDRESS = 'Email'
STACK_NAME = 'ArpioAccess'
ARPIO_TOKEN_COOKIE = 'ArpioSession'
NONE_ROLE = None
DEFAULT_TAG_RULE = "arpio-protected=true"

# HTTP helper functions
def http_get(url, headers=None):
    req = Request(url, headers=headers or {}, method='GET')
    try:
        with opener.open(req) as response:
            return response.read(), response.getcode(), response.headers
    except HTTPError as e:
        return e.read(), e.code, e.headers

def http_post(url, data=None, headers=None):
    json_data = json.dumps(data or {}).encode('utf-8')
    try:
        req = Request(url, data=json_data, headers=headers or {
            'Content-Type': 'application/json'
        }, method='POST')
        with opener.open(req) as response:
            return response.read(), response.getcode(), response.headers
    except HTTPError as e:
        return e.read(), e.code, e.headers

def get_cookie_value(name):
    for cookie in cookie_jar:
        if cookie.name == name:
            return cookie.value
    return None

# Helper Functions
def build_arpio_url(*path_bits):
    return '/'.join([ARPIO_API_ROOT] + list(path_bits))

def parse_environment(param_name, value):
    try:
        acct, region = value.split('/')[0:2]
    except ValueError:
        raise ValueError(f'{param_name} must be in format "account/region"')
    return (acct, region)

def build_tag_selection_rule(tag_key, tag_value=None):
    return {
        "ruleType": "tag",
        "name": tag_key,
        "value": tag_value
    }

def load_csv_data(csv_path):
    with open(csv_path, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        return list(reader)
    
def parse_tag_rules(tag_string:str) -> list[dict]:
    # parses a string of the form "key=value something=else and-a-third=true" and 
    # returns a list of dictionaries where ([key,value][something,else]])
    tag_rules = []
    split_tags = tag_string.split()
    for tagpair in split_tags:
        key, _, value  = tagpair.partition("=")
        tag_rules.append(build_tag_selection_rule(key,value))
    
    return tag_rules

def add_aws_account_id(account_id, aws_account_id, token):
    url = build_arpio_url(f'accounts/{account_id}/awsAccounts')
    payload = {
        'awsAccountId': aws_account_id,
        'name' : aws_account_id
        }
    body, code, _ = http_post(url, data= payload, headers={ARPIO_TOKEN_COOKIE: token, 'Content-Type': 'application/json'})
    if code not in {204,409,200}:
        raise Exception(f'Failed to add aws account: {body.decode()} ')


# Application Functions
def get_arpio_token(account_id, username, password):
    list_apps_url = build_arpio_url(f'accounts/{account_id}/applications')
    body, status, _ = http_get(list_apps_url)
    if status != 401:
        raise Exception('Expected 401 on unauthenticated GET operation')
    
    auth_url = json.loads(str(body, 'utf-8')).get('authenticateUrl')
    if not auth_url:
        raise Exception('No authentication URL in 401 response')
    
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

def get_assumed_session(boto_session, environment, role):
    region_name = environment[1]
    sts = boto_session.client('sts', region_name=region_name)
    role_arn = f'arn:aws:iam::{environment[0]}:role/{role}'
    assumed = sts.assume_role(RoleArn=role_arn, RoleSessionName='arpio_provisioning')
    assumed_session = Session(
        aws_access_key_id=assumed['Credentials']['AccessKeyId'],
        aws_secret_access_key=assumed['Credentials']['SecretAccessKey'],
        aws_session_token=assumed['Credentials']['SessionToken'],
        region_name=region_name
    )
    assumed_sts = assumed_session.client('sts')
    caller = assumed_sts.get_caller_identity()
    return assumed_session, caller

def get_access_templates(arpio_account, prod, recovery, token):
    url = build_arpio_url('accounts', arpio_account, 'syncPairs',
                          prod[0], prod[1], recovery[0], recovery[1], 'accessTemplates')
    body, code, _ = http_get(url, headers={'Cookie': f'{ARPIO_TOKEN_COOKIE}={token}'})
    if code != 200:
        raise Exception(f'Failed to get access templates: {body.decode()}')
    templates = json.loads(body)

    return templates['sourceTemplateS3Url'], templates['targetTemplateS3Url']

def install_access_template(session, aws_account, region, template_url, stack_name):
    print(f'\nInstalling access template in {aws_account}/{region}', end='', flush=True)
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
        else: raise ce

    done = False
    while not done:
        time.sleep(5)
        print('.', end='', flush=True)
        stack_details = cfn.describe_stacks(StackName=stack_name)['Stacks'][0]
        status = stack_details['StackStatus']
        failed_status = {'CREATE_FAILED', 'DELETE_COMPLETE', 'DELETE_FAILED',
                         'ROLLBACK_FAILED', 'ROLLBACK_COMPLETE', 'UPDATE_FAILED',
                         'UPDATE_ROLLBACK_FAILED', 'UPDATE_ROLLBACK_COMPLETE'}
        success_status = {'CREATE_COMPLETE', 'UPDATE_COMPLETE'}
        if status in failed_status:
            raise Exception(f'Stack application failed in {region}.')
        if status in success_status:
            done = True
            print('done')
def inform_of_aws_account(arpio_account, aws_account_id, token):
    account_get_url = build_arpio_url('accounts', arpio_account, 'awsAccounts', aws_account_id)
    body, code, _ =http_get(account_get_url, headers={'Cookie': f'{ARPIO_TOKEN_COOKIE}={token}'})
    if code == 404:
        account_post_url = build_arpio_url('accounts', arpio_account, 'awsAccounts')
        account_payload = {
            "awsAccountId": aws_account_id,
            "name": aws_account_id,
        }
        body, code, _ =http_post(account_post_url, data=account_payload, headers={'Cookie': f'{ARPIO_TOKEN_COOKIE}={token}'})
    if code != 201:
        raise Exception(f'Failed to create aws account: {body.decode()}')
            
def create_application_call(arpio_account, prod, recovery, emails, token, application_name, selection_rules, rpo):
    application_url = build_arpio_url('accounts', arpio_account, 'applications')
    print(application_url)
    application_payload = {
        "name": application_name,
        "accountId": arpio_account,
        "sourceAwsAccountId": prod[0],
        "sourceRegion": prod[1],
        "targetAwsAccountId": recovery[0],
        "targetRegion": recovery[1],
        "selectionRules": selection_rules,
        "rpo": rpo * 60,
        "notificationEmails": emails
    }
    body, code, _ = http_post(application_url, data= application_payload, headers={ARPIO_TOKEN_COOKIE: token, 'Content-Type': 'application/json'})
    if code != 201:
        raise Exception(f'Failed to create application: {body.decode()}')

    print(f'Arpio application "{application_name}" has been created.')

def create_application(row, arpio_account, token):
    primary_environment = parse_environment('primary-environment', row['primary_environment'])
    recovery_environment = parse_environment('recovery-environment', row['recovery_environment'])
    application_name = row['application_name']
    row_tag_rules = row.get('tag_rules', '').strip()
    tag_rules = parse_tag_rules(row_tag_rules or DEFAULT_TAG_RULE)
    recovery_point_objective = int(row.get('recovery_point_objective', 60))
    notification_email = row.get('notification_email', DEFAULT_NOTIFICATION_ADDRESS)

    add_aws_account_id(arpio_account, primary_environment[0], token)
    add_aws_account_id(arpio_account, recovery_environment[0], token)
    
    create_application_call(
        arpio_account,
        primary_environment,
        recovery_environment,
        [notification_email],
        token,
        application_name,
        tag_rules,  # Tag selection rules
        recovery_point_objective # default 60m
    )
    return row  # return the row for further processing

def access_template_provisioning(row, arpio_account, token):
    try:
        primary_environment = parse_environment('primary-environment', row['primary_environment'])
        recovery_environment = parse_environment('recovery-environment', row['recovery_environment'])

        primary_iam_role = row.get('primary_iam_role', NONE_ROLE)
        if not primary_iam_role:
            primary_iam_role = NONE_ROLE
        recovery_iam_role = row.get('recovery_iam_role', NONE_ROLE)
        if not recovery_iam_role:
            recovery_iam_role = NONE_ROLE

        session = Session()
        primary_session = Session(region_name=primary_environment[1])
        recovery_session = Session(region_name=recovery_environment[1])

        if primary_iam_role != NONE_ROLE:
            primary_session, _ = get_assumed_session(session, primary_environment, primary_iam_role)
        if recovery_iam_role != NONE_ROLE:
            recovery_session, _ = get_assumed_session(session, recovery_environment, recovery_iam_role)

        src_template, tgt_template = get_access_templates(arpio_account, primary_environment, recovery_environment, token)
        primary_stack_name = src_template.split('/')[-1][0:-4]
        recover_stack_name = tgt_template.split('/')[-1][0:-4]

        with ThreadPoolExecutor() as executor:
            src_future = executor.submit(install_access_template, primary_session, primary_environment[0], primary_environment[1], src_template, primary_stack_name)
            tgt_future = executor.submit(install_access_template, recovery_session, recovery_environment[0], recovery_environment[1], tgt_template, recover_stack_name)
            try:
                src_future.result()
                tgt_future.result()
            except Exception as e:
                print(f"Error installing access template for application {row.get('application_name')}: {e}")

    except Exception as e:
        print(f"Error in provisioning: {e}")
        raise e
     

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python onboard.py input.csv")
        sys.exit(1)
    
    check_version()

    print("=== Arpio Onboarding Script ===")
    print(f'Arpio Environment: [{ARPIO_API_ROOT}]')
    arpio_account = input(f'Arpio account ID [{DEFAULT_ARPIO_ACCOUNT}]: ') or DEFAULT_ARPIO_ACCOUNT
    username = input(f'Arpio username [{DEFAULT_ARPIO_USER}]: ') or DEFAULT_ARPIO_USER
    password = getpass.getpass('Arpio password: ')

    csv_file = sys.argv[1]
    data_rows = load_csv_data(csv_file)
    token = get_arpio_token(arpio_account, username, password)


    # Phase 1: create applications in parallel
    created_rows = []
    print("\n--- Creating applications in parallel ---")
    with ThreadPoolExecutor() as executor:
        future_to_row = {executor.submit(create_application, row, arpio_account, token): row for row in data_rows}
        for future in as_completed(future_to_row):
            try:
                result_row = future.result()
                created_rows.append(result_row)
            except Exception as e:
                print(f"Error creating application for row: {future_to_row[future].get('application_name')}: {e}")

    # Phase 2: install templates sequentially
    print("\n--- Installing access templates and finishing provisioning ---")
    for i, row in enumerate(data_rows):
        print(f"\n--- Access Template provisioning for application {i + 1} of {len(data_rows)}: {row.get('application_name')} ---")
        try:
            access_template_provisioning(row, arpio_account, token)
        except Exception as e:
            print(f"Error in Template Provisioning row {i + 1}: {e}")
