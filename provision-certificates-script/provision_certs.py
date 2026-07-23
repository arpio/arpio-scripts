# Copyright 2024 Arpio, Inc.

# This script queries Arpio for missing certificate issues, and then automates the provisioning
# of the correct certificate.

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
# Invoke the script optionally passing args for the Arpio account ID and credentials:
#   Windows: py provision_certs.py
#   Linux/Mac: python3 provision_certs.py
# To test the script, specify the --dry-run flag
#
# Authentication
# This script supports two ways of authenticating to the Arpio API (matching the other
# scripts in this repo):
#   - API Key:   pass via -k/--api-key or set the ARPIO_API_KEY environment variable, and
#                use -t/--auth-type api
#   - Token:     pass via -u/--username and -p/--password (or set ARPIO_USERNAME /
#                ARPIO_PASSWORD), and use -t/--auth-type token (the default)
#
# Examples:
#   python3 provision_certs.py -a <account-id> -t api -k <apiKeyID>:<secret>
#   python3 provision_certs.py -a <account-id> -t token -u user@example.com -p password
#   ARPIO_API_KEY="keyId:secret" python3 provision_certs.py -a <account-id> -t api
#
# If your Arpio account is configured to use SSO, you will need to set the auth_url variable in this script below
# to the identity provider url or use the --auth-url flag (token authentication only).

# Ex. - https://api.arpio.io/api/auth/authenticate?identityProviderId=example
auth_url = None

from datetime import datetime
import json
import os
import random
import string
import time
import requests
import click
import re
from boto3.session import Session
from botocore.exceptions import ClientError
from urllib.parse import urlsplit, parse_qs, urljoin


ARPIO_API_ROOT = os.environ.get('ARPIO_API') or 'https://api.arpio.io/api'
DEFAULT_ARPIO_ACCOUNT = 'arpio-account-id'
DEFAULT_ARPIO_USER = 'arpio-user-email'
NO_FILE = 'none'

ARPIO_TOKEN_COOKIE = 'ArpioSession'

def build_arpio_url(*path_bits):
    """Built an Arpio API URL from a set of path bits"""
    url_bits = [ARPIO_API_ROOT]
    url_bits.extend(path_bits)
    return '/'.join(url_bits)

def get_arpio_token(account_id, username, password, auth_url):
    """
    Given a username and password, get an access token for calling the Arpio API.
    This mirrors the UI flow in some pretty gnarly web requests.  Probably best to
    never touch this function -- let the Arpio team deal with it.
    """
    """Check if URL matches the Arpio auth authenticate pattern."""

    pattern = r'^https://api\.arpio\.io/api/auth/authenticate\?identityProviderId=[a-zA-Z0-9]+$'
    if auth_url and not re.match(pattern, auth_url):
        raise Exception('Provided Auth URL is invalid')

    # Attempt to list the applications in an account 
    list_apps_url = build_arpio_url(f'accounts/{account_id}/applications')
    resp = requests.get(list_apps_url)
    if resp.status_code != 401:
        raise Exception('Expected 401 on unauthenticated GET operation')
    
    if auth_url is None:
        auth_url = resp.json().get('authenticateUrl')
        if not auth_url:
            raise Exception("Didn't get an authentication URL in 401 reponse")
        
    if not auth_url:
        raise Exception("Authentication URL not provided")

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

def authenticate(auth_type, account_id, username, password, api_key, auth_url):
    """
    Resolve credentials and return an auth descriptor usable with auth_request_kwargs().

    For 'api' auth, the API key is taken from the --api-key arg, then the ARPIO_API_KEY
    environment variable, then an interactive prompt.

    For 'token' auth, the username/password are taken from args, then the ARPIO_USERNAME /
    ARPIO_PASSWORD environment variables, then interactive prompts, and are exchanged for an
    Arpio session token via the standard auth flow.
    """
    if auth_type == 'api':
        api_key = api_key or os.environ.get('ARPIO_API_KEY')
        if not api_key:
            api_key = click.prompt('Arpio API key (<apiKeyID>:<secret>)', hide_input=True)
        if not api_key:
            raise Exception('An API key is required for --auth-type api')
        return {'type': 'api', 'api_key': api_key}
    else:
        username = username or os.environ.get('ARPIO_USERNAME')
        if not username:
            username = click.prompt('Arpio username')
        password = password or os.environ.get('ARPIO_PASSWORD')
        if not password:
            password = click.prompt('Arpio password', hide_input=True)
        token = get_arpio_token(account_id, username, password, auth_url)
        return {'type': 'token', 'token': token}

def auth_request_kwargs(auth):
    """Return the requests keyword args that apply the given auth descriptor."""
    if auth['type'] == 'api':
        return {'headers': {'X-Api-Key': auth['api_key']}}
    return {'cookies': {ARPIO_TOKEN_COOKIE: auth['token']}}

def get_account_id(sts_client):
    resp = sts_client.get_caller_identity()
    return resp['Account']

def list_applications(accountId, auth):
    applications_url = build_arpio_url('accounts', accountId, 'applications')
    resp = requests.get(applications_url, **auth_request_kwargs(auth))
    if resp.status_code != 200:
        raise Exception(f'Failed to list applications: {resp.content}')
    return resp.json()

def list_missing_cert_issues(accountId, applicationId, auth):
    issues_url = build_arpio_url('accounts', accountId, 'applications', applicationId, 'issues')
    resp = requests.get(issues_url, **auth_request_kwargs(auth))
    if resp.status_code != 200:
        raise Exception(f'Failed to list issues: {resp.content}')
    return [i['issue'] for i in resp.json() if i['issue']['type'] == 'acmCertificateNotFound']

def provision_cert(acm_client, _primary_account, _primary_region, recovery_account, recovery_region, 
                   subject_name, subject_alternative_names, _primary_cert_arn, dry_run):
    """
    Use the ACM API to request a DNS-validated certificate with the appropriate subject name and
    subject alternative names.  
    """

    print(f'Provisioning cert for {subject_name} with {len(subject_alternative_names)} SAN(s) in region {recovery_region}')

    # Look for an existing certificate before creating a new one.
    cert_arn = None
    paginator = acm_client.get_paginator('list_certificates')
    for page in paginator.paginate():
        for cert in page['CertificateSummaryList']:
            if cert['DomainName'] == subject_name and set(cert['SubjectAlternativeNameSummaries']) == set(subject_alternative_names):
                if cert['Status'] == 'ISSUED' and cert['NotAfter'] < datetime.now:
                    print(f'Cert {subject_name} appears to already be issued.')
                    return []
                elif cert['Status'] == 'PENDING_VALIDATION':
                    cert_arn = cert['CertificateArn']
                    break
        if cert_arn:
            break

    if dry_run:
        if not cert_arn:
            print(f'Skipping provisioning cert because this is a dry-run.')
        else:
            print(f'Certificate is already provisioned.')
    else:
        if not cert_arn:
            idempotency_token = ''.join(random.choices(string.ascii_uppercase + string.digits, k=32))
            cert_arn = acm_client.request_certificate(
                DomainName=subject_name,
                ValidationMethod='DNS',
                SubjectAlternativeNames=subject_alternative_names,
                IdempotencyToken=idempotency_token,
            )['CertificateArn']
        
        for i in range(30):
            try:
                cert_details = acm_client.describe_certificate(CertificateArn=cert_arn)
                # DomainValidationOptions shows up latently
                if all('ResourceRecord' in dvo for dvo in cert_details['Certificate'].get('DomainValidationOptions', [{}])):
                    break
                time.sleep(5)
            except ClientError as ce:
                if ce.response['Error']['Code'] == 'ResourceNotFoundException':
                    time.sleep(5)
                else:
                    raise
        
        if not cert_details:
            raise Exception(f'Certificate {cert_arn} was successfully requested, but never appeared.')

        return [(dvo['ResourceRecord']['Name'], dvo['ResourceRecord']['Value']) for dvo in cert_details['Certificate']['DomainValidationOptions'] 
                if dvo.get('ValidationMethod') == 'DNS']
    return []

    

# This script makes heavy use of click for command-line processing.
# Details at https://palletsprojects.com/p/click/
@click.command()
@click.option('-a', '--arpio-account', prompt='Arpio account ID', default=DEFAULT_ARPIO_ACCOUNT, show_default=True)
@click.option('-t', '--auth-type', type=click.Choice(['api', 'token']), default='token', show_default=True,
              help='Authentication method: "api" for API key, "token" for username/password')
@click.option('-u', '--username', default=None, help='Arpio username (for token auth)')
@click.option('-p', '--password', default=None, help='Arpio password (for token auth)')
@click.option('-k', '--api-key', default=None, help='Arpio API key in the form "<apiKeyID>:<secret>" (for API auth)')
@click.option('-o', '--outfile', prompt='DNS entry output file', default=NO_FILE, show_default=True)
@click.option('-d', '--dry-run', is_flag=True)
@click.option('--auth-url', default=auth_url, show_default=True, prompt_required=False )

def provision(arpio_account, auth_type, username, password, api_key, dry_run, outfile, auth_url):

    # Resolve credentials to call the Arpio API
    auth = authenticate(auth_type, arpio_account, username, password, api_key, auth_url)

    # Validate that we have access to the AWS API, and identify the AWS account
    sts = Session().client('sts')
    account_id = get_account_id(sts)
    print(f'Current AWS account is {account_id}.  Certs required in other accounts will be skipped.\n')
    
    # Query for all defined applications
    applications = list_applications(arpio_account, auth)

    dns_entries = []

    # Iterate across all applications finding missing cert issues and provision them
    for app in applications:
        primary_account = app['sourceAwsAccountId']
        primary_region = app['sourceRegion']
        recovery_account = app['targetAwsAccountId']
        recovery_region = app['targetRegion']

        # Skip applications that replicate to other AWS accounts
        if recovery_account != account_id:
            continue

        missing_cert_issues = list_missing_cert_issues(arpio_account, app['appId'], auth)
        acm = Session(region_name=app['targetRegion']).client('acm')
        for issue in missing_cert_issues:
            primary_cert_arn = issue['sourceCertificateArn']
            subject_name = issue['domainName']
            subject_alternative_names = issue['subjectAlternativeNames']

            dns_entries.extend(
                provision_cert(acm, primary_account, primary_region, recovery_account, recovery_region, 
                           subject_name, subject_alternative_names, primary_cert_arn, dry_run)
            )

    if outfile is NO_FILE:
        print('\n========================== Required DNS Entries ==========================')
        if dry_run:
            print('None.  This is a dry run.')
        elif not dns_entries:
            print('None.')
        else:
            for n,v in dns_entries:
                print(f'CNAME Entry: {n} = {v}')
    else:
        of = open(outfile, '+w')
        data = [{'Name': n, 'Value': v} for n,v in dns_entries]
        json.dump(data, of)


if __name__ == '__main__':
    provision()



