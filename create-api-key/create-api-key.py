#!/usr/bin/env python
#
# Creates an API key in an Arpio account and prints an example of using it.
import json
import sys
from urllib.parse import urlsplit, parse_qs, urljoin

import click
import urllib3


class SessionError(Exception):
    pass


@click.command()
@click.argument('account-id')
@click.argument('email')
@click.option('--password', prompt='Password', hide_input=True)
@click.option('--api-hostname', default='api.arpio.io')
def cli(account_id: str, email: str, password: str, api_hostname: str):
    """
    Authenticate to an Arpio account using an email address and password and
    create an API key that can be used non-interactively to work with that
    account's resources.
    """
    # The account is a protected resource that requires authentication.
    account_uri = f'https://{api_hostname}/api/accounts/{account_id}'
    auth_flow_uri = f'https://{api_hostname}/api/accounts'
    http = urllib3.PoolManager()

    # Try to access the protected resource

    print(f'GET  {auth_flow_uri}')
    resp = http.request('GET', auth_flow_uri)
    if resp.status != 401:
        raise SessionError(f'Expected 401 on protected resource GET, but got {resp.status}')

    # Get the URL that starts an authentication flow for this resource

    auth_response = json.loads(resp.data)
    authenticate_url = auth_response.get('authenticateUrl')
    if not authenticate_url:
        raise SessionError('Empty authenticateUrl in 401 response: are you sure that resource URI exists?')

    # Make it absolute

    authenticate_url = urljoin(auth_flow_uri, authenticate_url)
    authenticate_url_parts = urlsplit(authenticate_url)

    # Start the authentication flow

    print(f'GET  {authenticate_url}')
    resp = http.request('GET', authenticate_url)
    if resp.status != 200:
        raise SessionError(f'{resp.status} starting authentication flow')

    # Read the loginUrl from the response
    web_login_url = json.loads(resp.data).get('loginUrl')
    if not web_login_url:
        raise SessionError('No loginUrl in response')

    # Extract the authToken from the loginUrl, since we're not really going to show the web UI for the native IdP

    login_url_parts = urlsplit(web_login_url)
    login_url_args = parse_qs(login_url_parts.query)
    auth_token = login_url_args.get('authToken', [])
    if not auth_token:
        raise SessionError(f'No authToken in authenticateUrl query arg: {authenticate_url}')
    auth_token = auth_token[0]

    # Login at the native IDP (which we assume is at the same scheme and proto as the protected resource)

    login_url = f'{authenticate_url_parts.scheme}://{authenticate_url_parts.netloc}/api/users/login'
    print(f'POST {login_url}')
    resp = http.request('POST', login_url, body=json.dumps({'email': email, 'password': password}),
                        headers={'Content-Type': 'application/json'})
    if resp.status != 200:
        raise SessionError(f'Login at native IDP failed: {resp.data}')

    native_auth_token = json.loads(resp.data).get('nativeAuthToken')
    if not native_auth_token:
        raise SessionError(f'No nativeAuthToken in native IDP response: {resp.data}')

    # Finish the flow
    native_acs_url = f'{authenticate_url_parts.scheme}://{authenticate_url_parts.netloc}/api/auth/nativeAcs'
    print(f'POST {native_acs_url}')
    resp = http.request('POST', native_acs_url,
                        body=json.dumps({'authToken': auth_token, 'nativeAuthToken': native_auth_token}),
                        headers={'Content-Type': 'application/json'})
    if resp.status != 200:
        raise SessionError(f'Login at native IDP failed: {resp.data}')

    session_cookie = resp.headers['set-cookie']
    session = session_cookie.split('=', 2)[1]

    # Use the interactive session cookie to create an API key.

    api_key_representation = {'name': f'Created by {email} with create-api-key.py'}
    api_keys_url = account_uri + '/apiKeys'
    headers = {'Cookie': f'ArpioSession={session}', 'Content-Type': 'application/json'}
    resp = http.request('POST', api_keys_url, headers=headers, body=json.dumps(api_key_representation))

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
    print(f'curl -H \'X-Api-Key: {api_key_id}:{api_key_secret}\' \'{api_keys_url}\'')


if __name__ == '__main__':
    try:
        cli()
    except SessionError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)