#!/usr/bin/env python3
# Copyright 2025 Arpio, Inc.

# This script updates the tag selection rules for every application in an Arpio account,
# setting them to arpio-protected:true.
#
# Supports two authentication methods:
#   - API Key: Pass via --api-key or set the ARPIO_API_KEY environment variable
#   - Token (username/password): Pass via --username/--password or set ARPIO_USERNAME/ARPIO_PASSWORD
#
# Usage examples:
#   python update_tag_rules.py -a <account-id> -t api -k "<keyId>:<secret>"
#   python update_tag_rules.py -a <account-id> -t token -u user@example.com -p password
#   ARPIO_API_KEY="keyId:secret" python update_tag_rules.py -a <account-id> -t api
#
# By default, sets the tag rule to arpio-protected=true. Override with --tag-key / --tag-value.

import json
import os
import sys
import getpass
import argparse
from urllib.parse import urlsplit, parse_qs, urljoin
from urllib.request import Request, build_opener, HTTPCookieProcessor, install_opener
from urllib.error import HTTPError
from http import cookiejar

# Defaults
ARPIO_API_ROOT = os.environ.get('ARPIO_API') or 'https://api.arpio.io/api'
ARPIO_TOKEN_COOKIE = 'ArpioSession'

cookie_jar = cookiejar.CookieJar()
cookie_handler = HTTPCookieProcessor(cookie_jar)
opener = build_opener(cookie_handler)
install_opener(opener)


# --------------- HTTP helpers (matching onboard.py patterns) ---------------

def http_get(url, headers=None):
    req = Request(url, headers=headers or {}, method='GET')
    try:
        with opener.open(req) as response:
            return response.read(), response.getcode(), response.headers
    except HTTPError as e:
        return e.read(), e.code, e.headers


def http_put(url, data=None, headers=None):
    json_data = json.dumps(data or {}).encode('utf-8')
    try:
        req = Request(url, data=json_data, headers=headers or {
            'Content-Type': 'application/json'
        }, method='PUT')
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
    return next((cookie.value for cookie in cookie_jar if cookie.name == name), None)


def build_arpio_url(*path_bits):
    return '/'.join([ARPIO_API_ROOT] + list(path_bits))


# --------------- Authentication ---------------

def authenticate_with_token(username, password):
    """Authenticate using username/password and return session-cookie auth header."""
    list_account_url = build_arpio_url('accounts')
    body, status, _ = http_get(list_account_url)
    if status != 401:
        raise Exception(f'Expected 401 on unauthenticated GET, got {status}')

    auth_url = json.loads(body.decode()).get('authenticateUrl')
    if not auth_url:
        raise Exception('No authenticateUrl in 401 response')

    auth_url = urljoin(list_account_url, auth_url)
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

    return {ARPIO_TOKEN_COOKIE: token}


def get_auth_header(args):
    """Return the appropriate auth header dict based on CLI args."""
    if args.auth_type == 'api':
        api_key = args.api_key or os.environ.get('ARPIO_API_KEY')
        if not api_key:
            api_key = getpass.getpass('Arpio API key (<keyId>:<secret>): ')
        if not api_key:
            print('Error: API key is required for --auth-type api')
            sys.exit(1)
        return {'X-Api-Key': api_key}
    else:
        username = args.username or os.environ.get('ARPIO_USERNAME')
        if not username:
            username = input('Arpio username (email): ')
        password = args.password or os.environ.get('ARPIO_PASSWORD')
        if not password:
            password = getpass.getpass('Arpio password: ')
        return authenticate_with_token(username, password)


# --------------- Core logic ---------------

def get_applications(account_id, auth_header):
    """GET /api/accounts/{account_id}/applications -> list of app dicts."""
    url = build_arpio_url('accounts', account_id, 'applications')
    body, code, _ = http_get(url, headers=auth_header)
    if code != 200:
        raise Exception(f'Failed to list applications (HTTP {code}): {body.decode()}')
    return json.loads(body.decode())


def update_application_tag_rules(account_id, app_id, selection_rules, auth_header):
    """PUT /api/accounts/{account_id}/applications/{app_id} with new selectionRules."""
    url = build_arpio_url('accounts', account_id, 'applications', app_id)
    payload = {'selectionRules': selection_rules}
    body, code, _ = http_put(url, data=payload,
                             headers=(auth_header | {'Content-Type': 'application/json'}))
    return body, code


def build_tag_selection_rule(tag_key, tag_value=None):
    return {
        "ruleType": "tag",
        "name": tag_key,
        "value": tag_value
    }


# --------------- Main ---------------

def main():
    parser = argparse.ArgumentParser(
        description='Update tag selection rules for all applications in an Arpio account.')
    parser.add_argument('-a', '--arpio-account', required=True,
                        help='Arpio Account ID')
    parser.add_argument('-t', '--auth-type', required=True, choices=['api', 'token'],
                        help='Authentication method: "api" for API key, "token" for username/password')
    parser.add_argument('-k', '--api-key',
                        help='Arpio API key in the form "<apiKeyID>:<secret>"')
    parser.add_argument('-u', '--username',
                        help='Arpio username (email)')
    parser.add_argument('-p', '--password',
                        help='Arpio password')
    parser.add_argument('--tag-key', default='arpio-protected',
                        help='Tag key to set (default: arpio-protected)')
    parser.add_argument('--tag-value', default='true',
                        help='Tag value to set (default: true)')
    parser.add_argument('--dry-run', action='store_true',
                        help='List applications and show what would change without making updates')
    args = parser.parse_args()

    account_id = args.arpio_account
    new_rule = [build_tag_selection_rule(args.tag_key, args.tag_value)]

    print("=== Arpio Tag Rule Updater ===")
    print(f"API root : {ARPIO_API_ROOT}")
    print(f"Account  : {account_id}")
    print(f"Tag rule : {args.tag_key}={args.tag_value}")
    if args.dry_run:
        print("Mode     : DRY RUN (no changes will be made)")
    print()

    # Authenticate
    try:
        auth_header = get_auth_header(args)
    except Exception as e:
        print(f"Authentication failed: {e}")
        sys.exit(1)

    # Fetch all applications
    try:
        applications = get_applications(account_id, auth_header)
    except Exception as e:
        print(f"Failed to retrieve applications: {e}")
        sys.exit(1)

    if not applications:
        print("No applications found in this account.")
        sys.exit(0)

    print(f"Found {len(applications)} application(s).\n")

    updated = 0
    skipped = 0
    failed = 0

    for app in applications:
        app_name = app.get('name', '(unnamed)')
        app_id = app.get('id')
        current_rules = app.get('selectionRules', [])

        if current_rules == new_rule:
            print(f"  SKIP  {app_name} (id={app_id}) — already has the target tag rule")
            skipped += 1
            continue

        print(f"  {'WOULD UPDATE' if args.dry_run else 'UPDATE'}  {app_name} (id={app_id})")
        print(f"          current rules: {json.dumps(current_rules)}")
        print(f"          new rules    : {json.dumps(new_rule)}")

        if args.dry_run:
            updated += 1
            continue

        body, code = update_application_tag_rules(account_id, app_id, new_rule, auth_header)
        if code in {200, 204}:
            print(f"          ✅ Updated successfully")
            updated += 1
        else:
            print(f"          ❌ Failed (HTTP {code}): {body.decode()}")
            failed += 1

    print(f"\nDone. Updated: {updated}, Skipped: {skipped}, Failed: {failed}")


if __name__ == '__main__':
    main()
