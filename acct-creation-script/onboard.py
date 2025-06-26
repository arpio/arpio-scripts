#!/usr/bin/env python3
# Copyright 2025 Arpio, Inc.

# This script is designed to automate the process of creating Arpio, an AWS disaster recovery service, Applications and their accompanying AWS CloudFormation templates.

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

#csv format
# production_environment,production_iam_role,recovery_environment,recovery_iam_role,arpio_account,username,password,application_name,recovery_point_objective (in minutes),notification_email
# 123456789012/us-east-1,MyProdRole,987654321098/us-west-2,MyRecRole,arpioaccountstring,example@example.com,YourPassword,TestApp,60,notify@example.com


import requests
import time
import os
import csv
import sys
import getpass
from boto3.session import Session
from botocore.exceptions import ClientError
from urllib.parse import urlsplit, parse_qs, urljoin

ARPIO_API_ROOT = os.environ.get('ARPIO_API') or 'https://api.arpio.io/api'
DEFAULT_ARPIO_ACCOUNT = 'arpio-account-id'
DEFAULT_ARPIO_USER = 'arpio-user-email'
DEFAULT_NOTIFICATION_ADDRESS = 'Email'
STACK_NAME = 'ArpioAccess'
ARPIO_TOKEN_COOKIE = 'ArpioSession'
NONE_ROLE = '<None>'


# ----------- Version Chec ----------
### Checks current Python version and warns on older than supported.
def check_version():
    # Checking Python version:
    expect_major = 3
    expect_minor = 12
    current_version = str(sys.version_info[0])+"."+str(sys.version_info[1])+"."+str(sys.version_info[2])
    print("INFO: Script developed and tested with Python " + str(expect_major) + "." + str(expect_minor))
    if (sys.version_info[0], sys.version_info[1]) < (expect_major, expect_minor):
        print("Current Python version is unsupported: Python " + current_version)

# ----------- Boto3 import check ----------   
try:
    from boto3.session import Session 
    from botocore.exceptions import ClientError     
except ImportError:
    print('The "boto3" package is not installed. Please install the AWS SDK for Python (Boto3) to continue, or run this script in an environment that has it.')
    exit()


def build_arpio_url(*path_bits):
    url_bits = [ARPIO_API_ROOT]
    url_bits.extend(path_bits)
    return '/'.join(url_bits)

def parse_environment(param_name, value):
    try:
        acct, region = tuple(value.split('/')[0:2])
    except ValueError:
        raise ValueError(f'{param_name} must be in format "account/region"')
    return (acct, region)

def get_arpio_token(account_id, username, password):
    list_apps_url = build_arpio_url(f'accounts/{account_id}/applications')
    resp = requests.get(list_apps_url)
    if resp.status_code != 401:
        raise Exception('Expected 401 on unauthenticated GET operation')

    auth_url = resp.json().get('authenticateUrl')
    if not auth_url:
        raise Exception("Didn't get an authentication URL in 401 response")

    auth_url = urljoin(list_apps_url, auth_url)
    auth_url_parts = urlsplit(auth_url)

    resp = requests.get(auth_url)
    if resp.status_code != 200:
        raise Exception(f'{resp.status_code} starting authentication flow')

    web_login_url = resp.json().get('loginUrl')
    if not web_login_url:
        raise Exception(f'No loginUrl in auth flow response')

    web_login_url_parts = urlsplit(web_login_url)
    web_login_url_args = parse_qs(web_login_url_parts.query)
    auth_token = web_login_url_args.get('authToken')
    if not auth_token:
        raise Exception(f'No authToken in auth URL: {web_login_url}')
    auth_token = auth_token[0]

    login_url = f'{auth_url_parts.scheme}://{auth_url_parts.netloc}/api/users/login'
    resp = requests.post(login_url, json={'email': username, 'password': password})
    if resp.status_code != 200:
        raise Exception(f'Failed to login: {resp.content}')

    native_auth_token = resp.json().get('nativeAuthToken')
    if not native_auth_token:
        raise Exception(f'No nativeAuthToken in native IDP response: {resp.content}')

    native_acs_url = f'{auth_url_parts.scheme}://{auth_url_parts.netloc}/api/auth/nativeAcs'
    resp = requests.post(native_acs_url, json={'authToken': auth_token, 'nativeAuthToken': native_auth_token})
    if resp.status_code != 200:
        raise Exception(f'Login at native IDP failed: {resp.content}')

    token = resp.cookies[ARPIO_TOKEN_COOKIE]
    return token

def get_assumed_session(boto_session, environment, role):
    sts = boto_session.client('sts')
    role_arn = f'arn:aws:iam::{environment[0]}:role/{role}'
    assumed = sts.assume_role(RoleArn=role_arn, RoleSessionName='arpio_provisioning')
    assumed_session = Session(
        aws_access_key_id=assumed['Credentials']['AccessKeyId'],
        aws_secret_access_key=assumed['Credentials']['SecretAccessKey'],
        aws_session_token=assumed['Credentials']['SessionToken'],
        region_name=environment[1]
    )
    assumed_sts = assumed_session.client('sts')
    caller = assumed_sts.get_caller_identity()
    return assumed_session, caller

def get_access_templates(arpio_account, prod, recovery, token):
    access_template_url = build_arpio_url('accounts', arpio_account, 'syncPairs',
                                          prod[0], prod[1], recovery[0], recovery[1], 'accessTemplates')
    r = requests.get(access_template_url, cookies={ARPIO_TOKEN_COOKIE: token})
    if r.status_code != 200:
        raise Exception(f'Failed to get access templates: {r.content}')
    templates = r.json()
    return templates['sourceTemplateS3Url'], templates['targetTemplateS3Url']

def install_access_template(session, aws_account, region, template_url, stack_name):
    print(f'Installing access template in {aws_account}/{region}', end='', flush=True)
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

def build_arn_selection_rule(resource_arns):
    return {
        "ruleType": "arn",
        "arns": resource_arns
    }

def build_tag_selection_rule(tag_key, tag_value=None):
    return {
        "ruleType": "tag",
        "name": tag_key,
        "value": tag_value
    }

def create_application(arpio_account, prod, recovery, emails, token, application_name, selection_rules, rpo):
    application_url = build_arpio_url('accounts', arpio_account, 'applications')
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
    r = requests.post(application_url, json=application_payload, cookies={ARPIO_TOKEN_COOKIE: token})
    if r.status_code != 201:
        raise Exception(f'Failed to create application: {r.content}')
    print(f'Arpio application "{application_name}" has been created.')

def inform_of_aws_account(arpio_account, aws_account_id, token):
    account_get_url = build_arpio_url('accounts', arpio_account, 'awsAccounts', aws_account_id)
    r = requests.get(account_get_url, cookies={ARPIO_TOKEN_COOKIE: token})
    if r.status_code == 404:
        account_post_url = build_arpio_url('accounts', arpio_account, 'awsAccounts')
        account_payload = {
            "awsAccountId": aws_account_id,
            "name": aws_account_id,
        }
        r = requests.post(account_post_url, json=account_payload, cookies={ARPIO_TOKEN_COOKIE: token})
        if r.status_code != 201:
            raise Exception(f'Failed to create aws account: {r.content}')

def load_csv_data(csv_path):
    with open(csv_path, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        return list(reader)

def create_from_csv(row, arpio_account, username, password):
    production_environment = parse_environment('production-environment', row['production_environment'])
    recovery_environment = parse_environment('recovery-environment', row['recovery_environment'])

    production_iam_role = row.get('production_iam_role', NONE_ROLE) or NONE_ROLE
    recovery_iam_role = row.get('recovery_iam_role', NONE_ROLE) or NONE_ROLE

    application_name = row['application_name']
    recovery_point_objective = int(row.get('recovery_point_objective', 60))
    notification_email = row.get('notification_email', DEFAULT_NOTIFICATION_ADDRESS)

    token = get_arpio_token(arpio_account, username, password)

    session = Session()
    production_session = Session(region_name=production_environment[1])
    recovery_session = Session(region_name=recovery_environment[1])

    if production_iam_role != NONE_ROLE:
        production_session, _ = get_assumed_session(session, production_environment, production_iam_role)
    if recovery_iam_role != NONE_ROLE:
        recovery_session, _ = get_assumed_session(session, recovery_environment, recovery_iam_role)

    src_template, tgt_template = get_access_templates(arpio_account, production_environment, recovery_environment, token)

    install_access_template(production_session, production_environment[0], production_environment[1], src_template, STACK_NAME)
    install_access_template(recovery_session, recovery_environment[0], recovery_environment[1], tgt_template, STACK_NAME)

    inform_of_aws_account(arpio_account, production_environment[0], token)
    inform_of_aws_account(arpio_account, recovery_environment[0], token)

    create_application(arpio_account, production_environment, recovery_environment, [notification_email], token,
                       application_name, [], recovery_point_objective)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python onboard.py input.csv")
        sys.exit(1)

    print("=== Arpio Onboarding Script ===")
    arpio_account = input(f'Arpio account ID [{DEFAULT_ARPIO_ACCOUNT}]: ') or DEFAULT_ARPIO_ACCOUNT
    username = input(f'Arpio username [{DEFAULT_ARPIO_USER}]: ') or DEFAULT_ARPIO_USER
    password = getpass.getpass('Arpio password: ')

    csv_file = sys.argv[1]
    data_rows = load_csv_data(csv_file)

    for i, row in enumerate(data_rows):
        print(f"\n--- Processing application {i + 1} of {len(data_rows)}: {row.get('application_name')} ---")
        try:
            create_from_csv(row, arpio_account, username, password)
        except Exception as e:
            print(f"Error processing row {i + 1}: {e}")
