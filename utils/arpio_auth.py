#!/usr/bin/env python3
# Copyright 2026 Arpio, Inc.

"""Shared Arpio API authentication helpers for the arpio-scripts CLIs.

This module gives every script a single, consistent set of command-line
arguments and one credential-resolution flow, so the scripts expose the same
flags and behave identically.  It depends only on the Python standard library,
so it can be imported by any script without adding dependencies.

Standard arguments (added by ``add_arpio_auth_args``):

    -a / --arpio-account   Arpio account ID
    -t / --auth-type       "api" or "token" (default: token)
    -k / --api-key         API key "<apiKeyID>:<secret>" (env: ARPIO_API_KEY)
    -u / --username        Arpio username/email          (env: ARPIO_USERNAME)
    -p / --password        Arpio password                (env: ARPIO_PASSWORD)

Credential resolution order for every value is: command-line argument, then
environment variable, then interactive prompt.

Typical usage in a script that talks to the Arpio API with urllib/urllib3::

    import argparse
    import arpio_auth

    parser = argparse.ArgumentParser()
    arpio_auth.add_arpio_auth_args(parser)
    args = parser.parse_args()

    auth = arpio_auth.resolve_auth(args)
    headers = arpio_auth.auth_headers(auth)   # {'X-Api-Key': ...} or {'ArpioSession': ...}

Scripts that use the ``requests`` library can instead apply
``arpio_auth.auth_request_kwargs(auth)`` to their requests calls.
"""

import getpass
import os
import re
import json
from http import cookiejar
from urllib.error import HTTPError
from urllib.parse import urlsplit, parse_qs, urljoin
from urllib.request import (
    Request,
    build_opener,
    HTTPCookieProcessor,
    HTTPHandler,
    HTTPSHandler,
    ProxyHandler,
)

# Arpio API root.  Override with the ARPIO_API environment variable.
ARPIO_API_ROOT = os.environ.get('ARPIO_API') or 'https://api.arpio.io/api'

# Name of the session cookie / header used for token (username+password) auth.
ARPIO_TOKEN_COOKIE = 'ArpioSession'

# Matches a single, well-formed email address (used to validate usernames).
_EMAIL_RE = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.[A-Za-z]{2,}')

# Opener + cookie jar used only for the token-exchange flow below.  Kept private
# so each script's own HTTP setup is unaffected.  Reconfigure with configure_http().
_cookie_jar = cookiejar.CookieJar()
_opener = build_opener(HTTPCookieProcessor(_cookie_jar))


def configure_http(proxy=False, debug_network=False):
    """Rebuild the internal auth opener to optionally use a proxy and/or debug logging.

    Call this before resolve_auth()/get_arpio_token() if the token-exchange flow
    needs to traverse a proxy server or log HTTP traffic for debugging.

    :param proxy: detect and use proxy settings from standard environment variables
    :param debug_network: enable verbose HTTP/S logging (INSECURE: logs tokens/keys)
    """
    global _opener
    handlers = [HTTPCookieProcessor(_cookie_jar)]
    if proxy:
        handlers.append(ProxyHandler())
    if debug_network:
        handlers.append(HTTPHandler(debuglevel=1))
        handlers.append(HTTPSHandler(debuglevel=1))
    _opener = build_opener(*handlers)


def build_arpio_url(*path_bits):
    """Build an Arpio API URL from a set of path components."""
    return '/'.join([ARPIO_API_ROOT] + [str(bit) for bit in path_bits])


def _http_get(url, headers=None):
    req = Request(url, headers=headers or {}, method='GET')
    try:
        with _opener.open(req) as response:
            return response.read(), response.getcode(), response.headers
    except HTTPError as e:
        return e.read(), e.code, e.headers


def _http_post(url, data=None, headers=None):
    json_data = json.dumps(data or {}).encode('utf-8')
    req = Request(url, data=json_data,
                  headers=headers or {'Content-Type': 'application/json'}, method='POST')
    try:
        with _opener.open(req) as response:
            return response.read(), response.getcode(), response.headers
    except HTTPError as e:
        return e.read(), e.code, e.headers


def _cookie_value(name):
    return next((cookie.value for cookie in _cookie_jar if cookie.name == name), None)


def add_arpio_auth_args(parser, account_required=True, default_auth_type='token'):
    """Add the standard Arpio authentication arguments to an argparse parser.

    :param parser: an argparse.ArgumentParser (or argument group) to add to
    :param account_required: whether -a/--arpio-account is required
    :param default_auth_type: default value for -t/--auth-type ("token" or "api")
    :returns: the same parser, for chaining
    """
    parser.add_argument('-a', '--arpio-account', required=account_required,
                        help='Arpio account ID')
    parser.add_argument('-t', '--auth-type', choices=['api', 'token'], default=default_auth_type,
                        help='Authentication method: "api" for API key, "token" for '
                             f'username/password (default: {default_auth_type})')
    parser.add_argument('-k', '--api-key',
                        help='Arpio API key in the form "<apiKeyID>:<secret>" '
                             '(or set the ARPIO_API_KEY environment variable)')
    parser.add_argument('-u', '--username',
                        help='Arpio username/email '
                             '(or set the ARPIO_USERNAME environment variable)')
    parser.add_argument('-p', '--password',
                        help='Arpio password '
                             '(or set the ARPIO_PASSWORD environment variable)')
    return parser


def get_arpio_token(username, password, auth_url=None):
    """Exchange a username and password for an Arpio session token.

    This mirrors the Arpio UI login flow.  It is intentionally low-level and
    should rarely need to change -- let the Arpio team maintain it.

    :param username: the Arpio username (email address)
    :param password: the Arpio password
    :param auth_url: optional explicit authenticate URL; when omitted it is
        discovered from the API's 401 response
    :returns: the Arpio session token string
    """
    list_account_url = build_arpio_url('accounts')

    if auth_url is not None:
        pattern = r'^https://api\.arpio\.io/api/auth/authenticate\?identityProviderId=[a-zA-Z0-9]+$'
        if not re.match(pattern, auth_url):
            raise Exception('Provided Auth URL is invalid')

    body, status, _ = _http_get(list_account_url)
    if status != 401:
        raise Exception(f'Expected 401 on unauthenticated GET operation, got {status}')

    if auth_url is None:
        auth_url = json.loads(body.decode()).get('authenticateUrl')
        if not auth_url:
            raise Exception('No authenticateUrl in 401 response')

    auth_url = urljoin(list_account_url, auth_url)
    auth_url_parts = urlsplit(auth_url)

    auth_body, code, _ = _http_get(auth_url)
    if code != 200:
        raise Exception(f'{code} starting authentication flow')

    web_login_url = json.loads(auth_body).get('loginUrl')
    if not web_login_url:
        raise Exception('No loginUrl in auth flow response')

    auth_token = parse_qs(urlsplit(web_login_url).query).get('authToken', [None])[0]
    if not auth_token:
        raise Exception(f'No authToken in URL: {web_login_url}')

    login_url = f'{auth_url_parts.scheme}://{auth_url_parts.netloc}/api/users/login'
    body, code, _ = _http_post(login_url, {'email': username, 'password': password})
    if code != 200:
        raise Exception(f'Login failed: {body.decode()}')

    native_auth_token = json.loads(body).get('nativeAuthToken')
    if not native_auth_token:
        raise Exception('Missing nativeAuthToken')

    native_acs_url = f'{auth_url_parts.scheme}://{auth_url_parts.netloc}/api/auth/nativeAcs'
    body, code, _ = _http_post(native_acs_url, {
        'authToken': auth_token,
        'nativeAuthToken': native_auth_token,
    })
    if code != 200:
        raise Exception(f'Native ACS login failed: {body.decode()}')

    token = _cookie_value(ARPIO_TOKEN_COOKIE)
    if not token:
        raise Exception('Failed to retrieve Arpio session token')

    return token


def resolve_auth(args, auth_url=None):
    """Resolve credentials from CLI args, environment, then prompts.

    :param args: parsed argparse namespace produced after add_arpio_auth_args()
    :param auth_url: optional explicit authenticate URL forwarded to get_arpio_token()
    :returns: an auth descriptor, one of:
        {'type': 'api', 'api_key': '<apiKeyID>:<secret>'}
        {'type': 'token', 'token': '<session-token>'}
    :raises Exception: if required credentials are missing or invalid
    """
    auth_type = getattr(args, 'auth_type', 'token')

    if auth_type == 'api':
        api_key = getattr(args, 'api_key', None) or os.environ.get('ARPIO_API_KEY')
        if not api_key:
            api_key = getpass.getpass('Arpio API key (<apiKeyID>:<secret>): ')
        if not api_key:
            raise Exception('An API key is required for --auth-type api')
        return {'type': 'api', 'api_key': api_key}

    username = getattr(args, 'username', None) or os.environ.get('ARPIO_USERNAME')
    if not username:
        username = input('Arpio username (email): ')
    if not _EMAIL_RE.fullmatch(username or ''):
        raise Exception(f'Invalid email address format: {username!r}')

    password = getattr(args, 'password', None) or os.environ.get('ARPIO_PASSWORD')
    if not password:
        password = getpass.getpass('Arpio password: ')

    token = get_arpio_token(username, password, auth_url=auth_url)
    return {'type': 'token', 'token': token}


def auth_headers(auth):
    """Return request headers for the given auth descriptor (urllib / urllib3 style).

    :param auth: a descriptor returned by resolve_auth()
    :returns: a dict of headers, e.g. {'X-Api-Key': ...} or {'ArpioSession': ...}
    """
    if auth['type'] == 'api':
        return {'X-Api-Key': auth['api_key']}
    return {ARPIO_TOKEN_COOKIE: auth['token']}


def auth_request_kwargs(auth):
    """Return keyword args for the ``requests`` library for the given auth descriptor.

    :param auth: a descriptor returned by resolve_auth()
    :returns: kwargs to splat into a requests call, e.g.
        {'headers': {'X-Api-Key': ...}} or {'cookies': {'ArpioSession': ...}}
    """
    if auth['type'] == 'api':
        return {'headers': {'X-Api-Key': auth['api_key']}}
    return {'cookies': {ARPIO_TOKEN_COOKIE: auth['token']}}


def resolve_auth_header(args, proxy=False, debug_network=False, auth_url=None):
    """Convenience wrapper: configure HTTP if needed, resolve credentials, return headers.

    Equivalent to calling configure_http() (when proxy/debug_network are set),
    resolve_auth(), then auth_headers().  Suited to scripts that authenticate
    with urllib/urllib3 using a header dict.

    :returns: a headers dict (see auth_headers())
    """
    if proxy or debug_network:
        configure_http(proxy=proxy, debug_network=debug_network)
    return auth_headers(resolve_auth(args, auth_url=auth_url))


def import_path_hint():
    """Return the directory containing this module, for sys.path insertion by callers."""
    return os.path.dirname(os.path.abspath(__file__))
