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
#   Windows: py create_validation_dns_entries.py
#   Linux/Mac: python3 create_validation_dns_entries.py
# To test the script, specify the --dry-run flag

from collections import defaultdict
from datetime import datetime
import json
import os
import random
import string
import time
import requests
import click
from boto3.session import Session
from botocore.exceptions import ClientError


def normalize_dns_name(dns_name):
    if dns_name[-1] == '.':
        return dns_name[:-1]
    return dns_name

def get_account_id(sts_client):
    resp = sts_client.get_caller_identity()
    return resp['Account']

def build_domain_zone_mapping(r53_client):
    mapping = defaultdict(set)
    paginator = r53_client.get_paginator('list_hosted_zones')
    for page in paginator.paginate():
        for zone in page['HostedZones']:
            mapping[normalize_dns_name(zone['Name'])].add(zone['Id'])

    return mapping

def find_hosted_zones(zone_mapping, entry_name):
    # Break the entry name apart into its pieces.  We need to search for a zone where we can create this entry
    entry_parts = entry_name.split('.')

    for i in range(len(entry_parts)):
        possible_zone_name = '.'.join(entry_parts[i:])
        if possible_zone_name in zone_mapping:
            return zone_mapping[possible_zone_name]

    return None

def find_resource_record_set(r53_client, entry_name, entry_value, zone_id):
    paginator = r53_client.get_paginator('list_resource_record_sets')
    for page in paginator.paginate(HostedZoneId=zone_id):
        for rrs in page['ResourceRecordSets']:
            if rrs['Type'] == 'CNAME' and normalize_dns_name(rrs['Name']) == entry_name and \
               rrs['ResourceRecords'] == [{'Value': entry_value}]:
                return rrs
    return None

def create_resource_record_set(r53_client, entry_name, entry_value, zone_id, dry_run):
    if dry_run:
        print(f'Not creating entry {entry_name} = {entry_value} because the dry-run flag was specified.')
    else:
        r53_client.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch = {
                'Changes': [
                    {
                        'Action': 'UPSERT',
                        'ResourceRecordSet': {
                            'Name': entry_name,
                            'Type': 'CNAME',
                            'ResourceRecords': [
                                {
                                    'Value': entry_value
                                }
                            ],
                            'TTL': 60
                        },
                    }
                ]
            }
        )
        print(f'Created entry {entry_name} = {entry_value}.')

def create_validation_entry(r53_client, zone_mapping, entry_name, entry_value, dry_run):
    entry_name = normalize_dns_name(entry_name)

    zone_ids = find_hosted_zones(zone_mapping, entry_name)

    if not zone_ids:
        print(f'Unable to find a hosted zone for {entry_name} in this AWS account.')
    else:
        for zone_id in zone_ids:
            rrs = find_resource_record_set(r53_client, entry_name, entry_value, zone_id)
            if rrs:
                print(f'CNAME entry {entry_name} = {entry_value} already exists in zone {zone_id}')
            else:
                create_resource_record_set(r53_client, entry_name, entry_value, zone_id, dry_run)

# This script makes heavy use of click for command-line processing.
# Details at https://palletsprojects.com/p/click/
@click.command()
@click.option('-f', '--entry-file', prompt='DNS entry input file created by the provision_certs.py script')
@click.option('-d', '--dry-run', is_flag=True)
def create_entries(entry_file, dry_run):
    # Validate that we have access to the AWS API, and identify the AWS account
    sts = Session().client('sts')
    account_id = get_account_id(sts)
    print(f'Current AWS account is {account_id}.  Route53 public zones in this account will be utilized.\n')

    ef = open(entry_file)
    entries = json.load(ef)

    r53 = Session().client('route53')

    # Produce a mapping of domain names to hosted zone IDs
    zone_mapping = build_domain_zone_mapping(r53)

    for entry in entries:
        create_validation_entry(r53, zone_mapping, entry['Name'], entry['Value'], dry_run)

if __name__ == '__main__':
    create_entries()

