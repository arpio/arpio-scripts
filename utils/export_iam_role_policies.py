#!/usr/bin/env python3
"""
Export IAM role policies to JSON file.
Usage: python export_iam_role_policies.py <role-arn> [--profile <profile>] [--output <filename>]
"""

import boto3
import json
import sys
import argparse
from urllib.parse import unquote


def get_role_name_from_arn(role_arn_or_name):
    """Extract role name from ARN or return the name if already a name."""
    if role_arn_or_name.startswith("arn:aws:iam::"):
        return role_arn_or_name.split('/')[-1]
    return role_arn_or_name


def get_role_policies(iam_client, role_name):
    """Get all policies attached to a role."""
    
    # Get role details
    try:
        role = iam_client.get_role(RoleName=role_name)['Role']
    except iam_client.exceptions.NoSuchEntityException:
        print(f"❌ Role '{role_name}' does not exist.")
        sys.exit(1)
    
    # Get attached managed policies
    attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
    if attached_policies:
        attached_policies = sorted(attached_policies, key=lambda x: x['PolicyName'])
    
    # Get inline policies
    inline_policy_names = iam_client.list_role_policies(RoleName=role_name)['PolicyNames']
    if inline_policy_names:
        inline_policy_names = sorted(inline_policy_names)
    
    result = {
        'role_name': role_name,
        'role_arn': role['Arn'],
        'attached_managed_policies': [],
        'inline_policies': []
    }
    
    # Process attached managed policies
    for policy in attached_policies:
        policy_arn = policy['PolicyArn']
        policy_details = iam_client.get_policy(PolicyArn=policy_arn)['Policy']
        
        policy_info = {
            'policy_name': policy['PolicyName'],
            'policy_arn': policy_arn,
            'policy_type': 'AWS Managed' if policy_arn.startswith('arn:aws:iam::aws:') else 'Customer Managed',
            'description': policy_details.get('Description', '')
        }
        
        # Get policy document for customer managed and some AWS managed policies
        # if policy_arn.startswith('arn:aws:iam::aws:policy/ReadOnlyAccess'):
        #     policy_info['note'] = 'This is an AWS managed policy with extensive read permissions across all AWS services. The full policy document is very large (truncated in output).'
        # else:
        version_id = policy_details['DefaultVersionId']
        policy_version = iam_client.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=version_id
        )['PolicyVersion']
        policy_info['policy_document'] = policy_version['Document']
        
        result['attached_managed_policies'].append(policy_info)
    
    # Process inline policies
    for policy_name in inline_policy_names:
        policy_doc = iam_client.get_role_policy(
            RoleName=role_name,
            PolicyName=policy_name
        )['PolicyDocument']
        
        result['inline_policies'].append({
            'policy_name': policy_name,
            'policy_type': 'Inline',
            'policy_document': policy_doc
        })
    
    return result


def main():
    parser = argparse.ArgumentParser(description='Export IAM role policies to JSON')
    parser.add_argument('role_input', help='IAM role name or ARN')
    parser.add_argument('--profile', help='AWS profile name', default=None)
    parser.add_argument('--output', help='Output filename (default: <role-name>.json)', default=None)
    
    args = parser.parse_args()
    
    # Create IAM client
    session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()
    iam_client = session.client('iam')
    
    # Extract role name from ARN or use as is if it's already a name
    role_name = get_role_name_from_arn(args.role_input)
    
    # Get all policies
    print(f"Fetching policies for role: {role_name}")
    policies = get_role_policies(iam_client, role_name)
    
    # Determine output filename
    if args.output:
        output_file = args.output
    else:
        # Extract a cleaner name from the role name
        # e.g., ArpioPrimaryAccess-iLGmukP1fRsL19GRTcOzAc-us-east-1 -> ArpioPrimaryAccess
        base_name = role_name.split('-')[0]
        output_file = f"{base_name}.json"
    
    # Write to file
    with open(output_file, 'w') as f:
        json.dump(policies, f, indent=2)
    
    print(f"Policies exported to: {output_file}")
    print(f"  - {len(policies['attached_managed_policies'])} attached managed policies")
    print(f"  - {len(policies['inline_policies'])} inline policies")


if __name__ == '__main__':
    main()
