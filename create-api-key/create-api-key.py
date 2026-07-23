#!/usr/bin/env python3
#
# Creates an API key in an Arpio account and prints an example of using it.
import argparse
import json
import os
import sys

import urllib3

# Import the shared Arpio authentication helpers from the sibling utils/ directory.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'utils'))
import arpio_auth


def main():
    """
    Authenticate to an Arpio account and create an API key that can be used
    non-interactively to work with that account's resources.

    By default this authenticates with a username/password (``-t token``);
    pass ``-t api`` with an existing API key to create another one.
    """
    parser = argparse.ArgumentParser(
        description='Create an Arpio API key for non-interactive use.')
    arpio_auth.add_arpio_auth_args(parser)
    args = parser.parse_args()

    # Resolve credentials (argument -> environment variable -> prompt).
    try:
        auth = arpio_auth.resolve_auth(args)
    except Exception as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)

    http = urllib3.PoolManager()
    api_keys_url = arpio_auth.build_arpio_url('accounts', args.arpio_account, 'apiKeys')

    label = args.username or os.environ.get('ARPIO_USERNAME') or 'create-api-key.py'
    api_key_representation = {'name': f'Created by {label} with create-api-key.py'}

    # Apply the resolved credentials.  For token auth, send the session as a
    # Cookie header (the form this endpoint expects); for API-key auth, send the
    # X-Api-Key header.
    if auth['type'] == 'api':
        headers = {'X-Api-Key': auth['api_key']}
    else:
        headers = {'Cookie': f"{arpio_auth.ARPIO_TOKEN_COOKIE}={auth['token']}"}
    headers['Content-Type'] = 'application/json'

    resp = http.request('POST', api_keys_url, headers=headers,
                        body=json.dumps(api_key_representation))
    if resp.status not in (200, 201):
        print(f'Failed to create API key (HTTP {resp.status}): '
              f'{resp.data.decode(errors="replace")}', file=sys.stderr)
        sys.exit(1)

    # Read the response to get the secret value, which can only ever be read one
    # time (this time).
    api_key_object = json.loads(resp.data)
    print('Created API key (the secret is only ever displayed ONE TIME, right here):')
    print(json.dumps(api_key_object, indent=2))

    api_key_id = api_key_object['apiKeyId']
    api_key_secret = api_key_object['secret']
    print()
    print('Example command using curl to list configured API keys:')
    print()
    print(f"curl -H 'X-Api-Key: {api_key_id}:{api_key_secret}' '{api_keys_url}'")


if __name__ == '__main__':
    main()
