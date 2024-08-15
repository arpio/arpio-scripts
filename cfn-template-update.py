#!/usr/bin/env python3

# Copyright 2024 Arpio, Inc.

# This script is designed to automate the process of updating AWS CloudFormation templates associated with applications managed by Arpio, an AWS disaster recovery service.

# First-time Setup Instructions
# 1. Make sure you have python 3 installed.  Get it here: https://www.python.org/downloads/
# 2. Copy this script and accompanying artifacts to a folder of your choosing.
# 3. Open a Windows Command Prompt or Linux/Mac Terminal and cd to the folder you chose in #2.
# 4. Run this command on Windows: py -m venv venv
#    or this command on Linux/Mac: python3 -m venv venv
# 5. Go run the Every-time Setup Instructions below

# Every-time Setup Instructions
# 1. Run this command on Windows: .\venv\Scripts\activate
#    or this command on Linux/Mac: . ./venv/bin/activate
# 2. Run this command: pip install -r requirements.txt

# Usage
# Invoke the script. When prompted, enter the following parameters:
# 1. Arpio Account ID (Navigate to Settings > Account in the Arpio console and copy the string following "Account ID: ")
# 2. Arpio User ID (This will be the email address you use to login to the Arpio application)
# 3. Arpio Password (The password you use to login the user ID from step 2)
# By default, the script will assume the IAM role: OrganizationAccountAccessRole for each AWS account associated with an Arpio Application.


import click
import requests
import time
import os
from csv import DictReader
from boto3.session import Session
from botocore.exceptions import ClientError


ARPIO_API_ROOT = os.environ.get('ARPIO_API') or 'https://api.arpio.io/api'
DEFAULT_ARPIO_ACCOUNT = ''
DEFAULT_ARPIO_USER = ''
ARPIO_TOKEN_COOKIE = 'ArpioSession'
DEFAULT_IAM_ROLE = 'OrganizationAccountAccessRole'



def get_arpio_token(account_id, username, password):
    """
    Given a username and password, get an access token for calling the Arpio API.
    This mirrors the UI flow in some pretty gnarly web requests.  Probably best to
    never touch this function -- let the Arpio team deal with it.
    """
    from urllib.parse import urlsplit, parse_qs, urljoin

    # Attempt to list the applications in an account 
    list_apps_url = build_arpio_url(f'accounts/{account_id}/applications')
    resp = requests.get(list_apps_url)
    if resp.status_code != 401:
        raise Exception('Expected 401 on unauthenticated GET operation')

    auth_url = resp.json().get('authenticateUrl')
    if not auth_url:
        raise Exception("Didn't get an authentication URL in 401 reponse")
    

    auth_url = urljoin(list_apps_url, auth_url)
    auth_url_parts = urlsplit(auth_url)

    # Start the auth flow
    resp = requests.get(auth_url)
    if resp.status_code != 200:
        raise Exception(f'{resp.status_code} starting authentication flow')

    # Get the auth token from the login URL
    web_login_url = resp.json().get('loginUrl')
    if not web_login_url:
        raise Exception(f'No loginUrl in auth flow repsonse')

    web_login_url_parts = urlsplit(web_login_url)
    web_login_url_args = parse_qs(web_login_url_parts.query)
    auth_token = web_login_url_args.get('authToken')
    if not auth_token:
        raise Exception(f'No authToken in auth URL: {web_login_url}')
    auth_token = auth_token[0]

    # Login at the native IDP
    login_url = f'{auth_url_parts.scheme}://{auth_url_parts.netloc}/api/users/login'
    resp = requests.post(login_url, json={'email':username, 'password': password})
    if resp.status_code != 200:
        raise Exception(f'Failed to login: {resp.content}')
    
    native_auth_token = resp.json().get('nativeAuthToken')
    if not native_auth_token:
        raise Exception(f'No nativeAuthToken in native IDP response: {resp.content}')
    
    # Finish the flow
    native_acs_url = f'{auth_url_parts.scheme}://{auth_url_parts.netloc}/api/auth/nativeAcs'
    resp = requests.post(native_acs_url, json={'authToken': auth_token, 'nativeAuthToken': native_auth_token})
    if resp.status_code != 200:
        raise Exception(f'Login at native IDP failed: {resp.content}')

    token = resp.cookies[ARPIO_TOKEN_COOKIE]
    return token

def get_assumed_session(boto_session, environment, role):
    """Get a boto session by assuming a role in an account."""
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

     
def query_applications(token, arpio_account):
    """Query for a list of all applications and convert them into a list of tuples with source account and source region."""
    # Construct the URL to query all applications for the given Arpio account
    applications_url = build_arpio_url('accounts', arpio_account, 'applications')
    
    # Make a GET request to the applications URL with the authentication token
    response = requests.get(applications_url, cookies={ARPIO_TOKEN_COOKIE: token})
    
    # Check if the request was successful (status code 200). If not, raise an exception.
    if response.status_code != 200:
        raise Exception(f'Failed to query applications: {response.content}')
    
    # Parse the JSON response to get the list of applications
    applications = response.json()

    # Use list comprehension to create a list of tuples (sourceAwsAccountId, sourceRegion, targetAwsAccountId, targetRegion) for each application
    app_tuples = [((app['sourceAwsAccountId'], app['sourceRegion']), (app['targetAwsAccountId'], app['targetRegion'])) for app in applications]
    
    
    # Return the list of tuples
    return app_tuples

def needs_template_update(token, arpio_account, source_account, source_region, target_account, target_region):
    """Check if the sync pair needs templates to be updated."""
    sync_pair_url = build_arpio_url('accounts', arpio_account, 'syncPairs', source_account, source_region, target_account, target_region, 'access')
    
    # Print the URL 
    print(f"Sync pair URL: {sync_pair_url}")
    
    # Make a GET request to the sync pair URL with the authentication token
    response = requests.get(sync_pair_url, cookies={ARPIO_TOKEN_COOKIE: token})
    
    # Check if the request was successful (status code 200). If not, raise an exception.
    if response.status_code != 200:
        print(f"Failed to query sync pair update status: {response.content}")
        raise Exception(f'Failed to query sync pair update status: {response.content}')
    
    # Parse the JSON response to determine if an update is needed
    update_info = response.json()
    print(f"Update info for {source_account}/{source_region} -> {target_account}/{target_region}: {update_info}")

    source_latest = update_info.get('sourceIsLatest', True)
    target_latest = update_info.get('targetIsLatest', True)
    
    if source_latest:
        source_stack = None
    else: 
        source_stack = update_info.get('sourceCloudFormationAccessStackName')


    if target_latest:
        target_stack = None
    else: 
        target_stack = update_info.get('targetCloudFormationAccessStackName')

    return (source_stack,target_stack)


def get_access_templates(arpio_account, prod, recovery, token):
    """
    Get the Arpio access templates for a given source and target.
    prod and recovery are 2-tuples with AWS account and region.
    """
    access_template_url = build_arpio_url('accounts', arpio_account, 'syncPairs', prod[0], prod[1], recovery[0], recovery[1], 'accessTemplates')
    r = requests.get(access_template_url, cookies={ARPIO_TOKEN_COOKIE: token})
    if r.status_code != 200:
        raise Exception(f'Failed to get access templates: {r.content}')
    templates = r.json()
    return templates['sourceTemplateS3Url'], templates['targetTemplateS3Url']


def install_access_template(session, aws_account, region, template_url, stack_name):
    """Install or update the access templates via CloudFormation"""
    click.echo(f'Installing access template in {aws_account}/{region}', nl=False)
    cfn = session.client('cloudformation')
    try:
        stack_id = cfn.update_stack(
            StackName=stack_name,
            TemplateURL=template_url,
            Capabilities=['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM']
        )

    except ClientError as ce:
        if ce.response['Error']['Code'] == 'ValidationError' and 'does not exist' in ce.response['Error']['Message']:
            # The stack doesn't exist
            stack_id = cfn.create_stack(
                StackName=stack_name,
                TemplateURL=template_url,
                Capabilities=['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM']
            )['StackId']

    done = False
    while not done:
        time.sleep(5)
        click.echo('.', nl=False)
        stack_details = cfn.describe_stacks(StackName=stack_name)['Stacks'][0]
        status = stack_details['StackStatus']

        failed_status = {'CREATE_FAILED', 'DELETE_COMPLETE', 'DELETE_FAILED', 'ROLLBACK_FAILED', 'ROLLBACK_COMPLETE', 'UPDATE_FAILED', 'UPDATE_ROLLBACK_FAILED', 'UPDATE_ROLLBACK_COMPLETE'}
        success_status = {'CREATE_COMPLETE', 'UPDATE_COMPLETE'}
        if status in failed_status:
            raise Exception(f'Stack application failed.  See details for stack "{stack_name}" in the CloudFormation console.')
        if status in success_status:
            done = True
            click.echo('done')


def build_arpio_url(*path_bits):
    """Built an Arpio API URL from a set of path bits"""
    url_bits = [ARPIO_API_ROOT]
    url_bits.extend(path_bits)
    return '/'.join(url_bits)

@click.command()
@click.option('-a', '--arpio-account', prompt='Arpio account ID', default=DEFAULT_ARPIO_ACCOUNT, show_default=True)
@click.option('-u', '--username', prompt='Arpio username', default=DEFAULT_ARPIO_USER, show_default=True)
@click.option('-p', '--password', prompt='Arpio password', hide_input=True) 
@click.option('-r', '--role-name', prompt='Name of Role that can be assumed in each AWS account', default=DEFAULT_IAM_ROLE) 
def main(arpio_account, username, password, role_name):
    # Get a token to call the Arpio API
    token = get_arpio_token(arpio_account, username, password)
    
    # Query applications and transform data
    app_tuples = query_applications(token, arpio_account)
    
    # Print or return the result as JSON
    print(app_tuples)

    session=Session()

    for (sourceAwsAccountId, sourceRegion), (targetAwsAccountId, targetRegion) in app_tuples:
        source_stack, target_stack = needs_template_update (token, arpio_account, sourceAwsAccountId, sourceRegion, targetAwsAccountId, targetRegion)
        if source_stack or target_stack:
            prod= (sourceAwsAccountId, sourceRegion)
            recovery= (targetAwsAccountId, targetRegion)
            source_template, target_template = get_access_templates(arpio_account, prod, recovery, token) 
            if source_stack:
                source_session, _ = get_assumed_session (session, prod, role_name)
                install_access_template (source_session, sourceAwsAccountId, sourceRegion, source_template, source_stack)
            if target_stack:
                target_session, _ = get_assumed_session (session, recovery, role_name)
                install_access_template (target_session, targetAwsAccountId, targetRegion, target_template, target_stack)


if __name__ == '__main__':
    main()
