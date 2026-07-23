#!/usr/bin/env python3
# Copyright 2025 Arpio, Inc.

# This script is designed to automate the process of creating Arpio Applications and 
# their accompanying AWS CloudFormation templates.

# First-time Setup Instructions
# 1. Make sure you have python >= 3.9 installed.  
#    Get it here: https://www.python.org/downloads
# 2. Make sure you have boto3 >=1.26.30 installed. 
#    See instructions here: https://boto3.amazonaws.com/v1/documentation/api/latest/guide/quickstart.html
# 2. Copy this script and accompanying artifacts to a folder of your choosing.
# 3. You will need to be logged in to Amazon Web Services and have sufficient permissions 
#    to assume the OrganizationAccountAccessRole or a role that can assume the necessary 
#    permissions to update CloudFormationTemplates across multiple accounts

# Usage
# Invoke the script, with the required command line argument of the CSV location, and 
# optional command line arguments for the Arpio Account ID, and either Arpio API key or Arpio Username/Password.
# If you use an SSO portal for login, it is recommended to use the API Key instead of token authorization
# The Arpio API can be provided via an environmental variable named ARPIO_API_KEY.
# The Arpio password can be provided via an environmental variable named ARPIO_PASSWORD.
#
# If the Arpio Account ID, and either Arpio API key or Arpio Username/Password aren't provided in the command line,
# when prompted, enter the following parameters:
#
# 1. Arpio Account ID (Navigate to Settings > Account in the Arpio console 
#    and copy the string following 'Account ID: ')
# 2. Arpio User ID (This will be the email address you use to login to the Arpio application)
# 3. Arpio Password 

# By default, the script will assume the IAM role: OrganizationAccountAccessRole 
# for each AWS account associated with an Arpio Application.

# .CSV file format example
# Header Columns: primary_environment,primary_iam_role,recovery_environment,recovery_iam_role,application_name,recovery_point_objective (in minutes),notification_email, tag_rules
# Examples: 123456789012/us-east-1,MyProdRole,987654321098/us-west-2,MyRecRole,TestApp,60,notify@example.com,key=value something=else and-a-third=true


import json
import time
import os
import csv
import sys
import getpass
import threading
import argparse
import re
from urllib.parse import urlsplit, parse_qs, urljoin
from urllib.request import Request, build_opener, HTTPCookieProcessor, HTTPHandler, HTTPSHandler, ProxyHandler, install_opener
from urllib.error import HTTPError
from concurrent.futures import ThreadPoolExecutor, as_completed
from http import cookiejar

# Import the shared Arpio authentication helpers from the sibling utils/ directory.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'utils'))
import arpio_auth

# Declare globals
ARPIO_API_ROOT = os.environ.get('ARPIO_API') or 'https://api.arpio.io/api'
DEFAULT_ARPIO_ACCOUNT = 'arpio-account-id'
DEFAULT_ARPIO_USER = 'arpio-user-email'
DEFAULT_NOTIFICATION_ADDRESS = 'Email'
STACK_NAME = 'ArpioAccess'
ARPIO_TOKEN_COOKIE = 'ArpioSession'
NONE_ROLE = None
DEFAULT_TAG_RULE = "arpio-protected=true"
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

# Helper Functions
def build_arpio_url(*path_bits):
    return '/'.join([ARPIO_API_ROOT] + list(path_bits))

def parse_environment(param_name, value):
    try:
        acct, region = value.split('/')[0:2]
    except ValueError:
        raise ValueError(f'❌ {param_name} must be in format "account/region"')
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
    if not tag_string.strip():
        return [build_tag_selection_rule('arpio-protected', 'true')]
    
    tag_rules = []
    split_tags = tag_string.split()
    for tagpair in split_tags:
        key, _, value  = tagpair.partition("=")
        tag_rules.append(build_tag_selection_rule(key,value))
    
    return tag_rules

def add_aws_account_id(account_id, aws_account_id, arpio_auth_header):
    url = build_arpio_url(f'accounts/{account_id}/awsAccounts')
    payload = {
        'awsAccountId': aws_account_id,
        'name' : aws_account_id
        }
    body, code, _ = http_get(url, headers=arpio_auth_header)
    if aws_account_id in body.decode():
        print(f'AWS account already added to Arpio')
        return

    body, code, _ = http_post(url, data= payload, headers=(arpio_auth_header | {'Content-Type': 'application/json'}))
    #Ignoring 409 as we return that for when an account already exists and the script should continue on to other applications if one fails.
    if code == 409:
        print(f'AWS account already added to Arpio')
        return
    if code not in {200,201,204}:
        raise Exception(f'❌ Failed to add aws account: {body.decode()} : Error: {code}')



# Application Functions
def get_assumed_session(environment, role):
    region_name = environment[1]
    boto_session = Session(region_name=region_name)
    sts = boto_session.client('sts', region_name=region_name) #If using opt-in regions, must have AWS_STS_REGIONAL_ENDPOINTS= 'regional' set
    aws_account = environment[0]
    role_arn = f'arn:aws:iam::{aws_account}:role/{role}'
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

def get_access_templates(arpio_account, prod, recovery, arpio_auth_header):
    url = build_arpio_url('accounts', arpio_account, 'syncPairs',
                          prod[0], prod[1], recovery[0], recovery[1], 'accessTemplates')
    body, code, _ = http_get(url, headers=arpio_auth_header)
    if code != 200:
        raise Exception(f'❌ Failed to get access templates: {body.decode()}')
    templates = json.loads(body)

    return templates['sourceTemplateS3Url'], templates['targetTemplateS3Url']

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
            safe_print(f'✅ Updated template in AWS: {aws_account}/{session.region_name}') 
            break
        elif 'FAILED' in status or 'ROLLBACK' in status:
            raise Exception(f'Stack operation failed: {status}')
            
def create_application_call(arpio_account, prod, recovery, emails, arpio_auth_header, application_name, selection_rules, rpo):
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

    body, code, _ = http_post(application_url, data= application_payload, headers=(arpio_auth_header | {'Content-Type': 'application/json'}))
    if code != 201:
        raise Exception(f'❌ Failed to create application: {body.decode()}')
    if code == 409:
        raise Exception(f'Application already exists, continuing...')
    else:
        safe_print(f'✅ Arpio application "{application_name}" has been created.')

def create_application(row, arpio_account, arpio_auth_header):
    primary_environment = parse_environment('primary-environment', row['primary_environment'])
    recovery_environment = parse_environment('recovery-environment', row['recovery_environment'])
    application_name = row['application_name']
    row_tag_rules = row.get('tag_rules', '').strip()
    tag_rules = parse_tag_rules(row_tag_rules or DEFAULT_TAG_RULE)
    recovery_point_objective = int(row.get('recovery_point_objective', 60))
    notification_email = row.get('notification_email', DEFAULT_NOTIFICATION_ADDRESS)

    ##check if application exists via name and skip if so
    body, code, _ = http_get(build_arpio_url('accounts', arpio_account, 'applications'), headers=arpio_auth_header)

    if str(application_name) in body.decode():
        print(f'Arpio Application with this name already exists, skipping creation...')
        return row
    else:
        with ThreadPoolExecutor() as executor:
            try:
                src_future = executor.submit(add_aws_account_id, arpio_account, primary_environment[0], arpio_auth_header)
            except Exception as e:
                print(e)
            try:
                tgt_future = executor.submit(add_aws_account_id, arpio_account, recovery_environment[0], arpio_auth_header)
            except Exception as e:
                print(e)
            src_future.result()
            tgt_future.result()
        try:
            create_application_call(
                arpio_account,
                primary_environment,
                recovery_environment,
                [notification_email],
                arpio_auth_header,
                application_name,
                tag_rules,  # Tag selection rules
                recovery_point_objective # default 60m
            )
        except Exception as e:
            print(e)
        return row  # return the row for further processing

def access_template_provisioning(row, arpio_account, arpio_auth_header):
    try:
        primary_environment = parse_environment('primary-environment', row['primary_environment'])
        recovery_environment = parse_environment('recovery-environment', row['recovery_environment'])

        primary_iam_role = row.get('primary_iam_role', NONE_ROLE)
        if not primary_iam_role:
            primary_iam_role = NONE_ROLE
        recovery_iam_role = row.get('recovery_iam_role', NONE_ROLE)
        if not recovery_iam_role:
            recovery_iam_role = NONE_ROLE
     
        primary_session = Session(region_name=primary_environment[1])
        recovery_session = Session(region_name=recovery_environment[1])

        if primary_iam_role != NONE_ROLE:
            primary_session, _ = get_assumed_session(primary_environment, primary_iam_role)
        if recovery_iam_role != NONE_ROLE:
            recovery_session, _ = get_assumed_session(recovery_environment, recovery_iam_role)

        src_template, tgt_template = get_access_templates(arpio_account, primary_environment, recovery_environment, arpio_auth_header)

        #Splits Signed stack name file from URL, then stack name from signed yaml
        primary_stack_name = (src_template.split('/')[-1]).split('.')[0]
        recovery_stack_name = (tgt_template.split('/')[-1]).split('.')[0]

        with ThreadPoolExecutor() as executor:
            src_future = executor.submit(install_access_template, primary_session, primary_environment[0], primary_environment[1], src_template, primary_stack_name)
            tgt_future = executor.submit(install_access_template, recovery_session, recovery_environment[0], recovery_environment[1], tgt_template, recovery_stack_name)
            
            try:
                src_future.result()

            except Exception as e:
                error = str(e)
                if "ValidationError" in error and "No updates are to be performed" in error:
                    print(f"Stack {primary_environment} is already up to date - no changes needed")
                else:
                    print(f"An unexpected error occurred: {error}")
                    raise Exception(f"❌ Error installing access template for application {row.get('application_name')}: {e}")

            try:
                tgt_future.result()

            except Exception as e:
                error = str(e)
                if "ValidationError" in error and "No updates are to be performed" in error:
                    print(f"Stack {recovery_environment} is already up to date - no changes needed")
                else:
                    print(f"An unexpected error occurred: {error}")
                    raise Exception(f"❌ Error installing access template for application {row.get('application_name')}: {e}")

    except Exception as e:
        print(f"❌ Error in provisioning: {e}")
        raise e
     

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Arpio Onboarding Script')
    parser.add_argument('-c', '--csv', help='Path to input CSV file')
    arpio_auth.add_arpio_auth_args(parser)
    parser.add_argument('--proxy', help='Flag to indicate the usage of a proxy server. Proxy server must be kept in standard environment variables for autodetection to work.', action='store_true', default=False)
    parser.add_argument('-n', '--debug-network', help='Flag to enable HTTP/S Network Debugging flagging. Insecure, will log Tokens/Keys for debugging.', action='store_true', default=False)
    args = parser.parse_args()

    setup_handler(args.debug_network, args.proxy)
    
    print("=== Arpio Onboarding Script ===")
    print(f'Arpio Environment: [{ARPIO_API_ROOT}]')

    arpio_account = args.arpio_account

    try:
        arpio_auth_header = arpio_auth.resolve_auth_header(
            args, proxy=args.proxy, debug_network=args.debug_network)
    except Exception as e:
        print(f"{e}")
        sys.exit(1)


    csv_file = args.csv
    data_rows = load_csv_data(csv_file)



    # Phase 1: create applications in parallel
    created_rows = []
    print("\n--- Creating applications in parallel ---")
    with ThreadPoolExecutor() as executor:
        future_to_row = {executor.submit(create_application, row, arpio_account, arpio_auth_header): row for row in data_rows}
        for future in as_completed(future_to_row):
            try:
                result_row = future.result()
                created_rows.append(result_row)
            except Exception as e:
                safe_print(f"❌ Error creating application for row: {future_to_row[future].get('application_name')}: {e}")

    # Phase 2: install templates sequentially
    print("\n--- Installing access templates and finishing provisioning ---")
    for i, row in enumerate(data_rows):
        print(f"\n--- Access Template provisioning for application {i + 1} of {len(data_rows)}: {row.get('application_name')} ---")
        try:
            access_template_provisioning(row, arpio_account, arpio_auth_header)
        except Exception as e:
            safe_print(f"❌ Error in Template Provisioning row {i + 1}: {e}")

    