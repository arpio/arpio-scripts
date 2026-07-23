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
# Invoke the script optionally passing args for the Arpio account ID, Arpio username, and/or password:
#   Windows: py provision_certs.py
#   Linux/Mac: python3 provision_certs.py
# To test the script, specify the --dry-run flag
#
# If your Arpio account is configured to use SSO, you will need to set the auth_url variable in this script below 
# to the identity provider url or use the --auth-url flag.

# Ex. - https://api.arpio.io/api/auth/authenticate?identityProviderId=example
auth_url = None

from datetime import datetime
import argparse
import json
import os
import random
import string
import sys
import time
import requests
from boto3.session import Session
from botocore.exceptions import ClientError

# Import the shared Arpio authentication helpers from the sibling utils/ directory.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'utils'))
import arpio_auth


ARPIO_API_ROOT = os.environ.get('ARPIO_API') or 'https://api.arpio.io/api'
NO_FILE = 'none'


def build_arpio_url(*path_bits):
    """Built an Arpio API URL from a set of path bits"""
    url_bits = [ARPIO_API_ROOT]
    url_bits.extend(path_bits)
    return '/'.join(url_bits)

def get_account_id(sts_client):
    resp = sts_client.get_caller_identity()
    return resp['Account']

def list_applications(accountId, auth):
    applications_url = build_arpio_url('accounts', accountId, 'applications')
    resp = requests.get(applications_url, **arpio_auth.auth_request_kwargs(auth))
    if resp.status_code != 200:
        raise Exception(f'Failed to list applications: {resp.content}')
    return resp.json()

def list_missing_cert_issues(accountId, applicationId, auth):
    issues_url = build_arpio_url('accounts', accountId, 'applications', applicationId, 'issues')
    resp = requests.get(issues_url, **arpio_auth.auth_request_kwargs(auth))
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

    

def main():
    parser = argparse.ArgumentParser(
        description='Provision missing recovery-side ACM certificates for Arpio applications.')
    arpio_auth.add_arpio_auth_args(parser)
    parser.add_argument('-o', '--outfile', default=NO_FILE,
                        help='File to write required DNS entries to as JSON '
                             '(default: print to stdout)')
    parser.add_argument('-d', '--dry-run', action='store_true',
                        help='Report what would be provisioned without making changes')
    parser.add_argument('--auth-url', default=auth_url,
                        help='Explicit Arpio identity-provider authenticate URL '
                             '(for SSO accounts, token auth only)')
    args = parser.parse_args()

    arpio_account = args.arpio_account
    dry_run = args.dry_run
    outfile = args.outfile

    # Resolve credentials to call the Arpio API
    try:
        auth = arpio_auth.resolve_auth(args, auth_url=args.auth_url)
    except Exception as e:
        print(f'{e}')
        sys.exit(1)

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

        missing_cert_issues = list_missing_cert_issues(arpio_account, app['appId'], token)
        acm = Session(region_name=app['targetRegion']).client('acm')
        for issue in missing_cert_issues:
            primary_cert_arn = issue['sourceCertificateArn']
            subject_name = issue['domainName']
            subject_alternative_names = issue['subjectAlternativeNames']

            dns_entries.extend(
                provision_cert(acm, primary_account, primary_region, recovery_account, recovery_region, 
                           subject_name, subject_alternative_names, primary_cert_arn, dry_run)
            )

    if outfile == NO_FILE:
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
    main()



