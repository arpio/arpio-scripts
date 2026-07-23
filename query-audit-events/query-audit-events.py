#!/usr/bin/env python3
import argparse
import json
import os
import sys
from datetime import timezone
from urllib.parse import urlencode

import urllib3
from dateutil.parser import DEFAULTPARSER, ParserError

# Import the shared Arpio authentication helpers from the sibling utils/ directory.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'utils'))
import arpio_auth


def parse_time_arg(value, arg_name):
    """
    Parse a time argument given on the command line and return it as an
    ISO 8601 string to send to the API.  The input value may contain
    a timezone.  If it doesn't, the value is interpreted in the local
    computer's time zone.  The returned value is always in UTC.

    :param value: the value to parse or None to get the current time
    :param arg_name: the argument name, for errors
    :returns: an ISO 8601 string in UTC time zone
    """
    try:
        dt = DEFAULTPARSER.parse(value)
    except ParserError as e:
        raise SystemExit(f'Invalid value for the {arg_name} argument: {e}')

    # Convert to UTC if needed.
    if not dt.utcoffset() or dt.utcoffset().total_seconds() != 0:
        dt = dt.astimezone(timezone.utc)

    return dt.strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def main():
    """
    Retrieves Arpio audit events for the specified account that match the
    specified time frame.  Audit events are printed to stdout in JSON lines
    (JSONL) format.

    By default this authenticates with an API key (``-t api``), taken from
    ``-k/--api-key`` or the ARPIO_API_KEY environment variable; pass
    ``-t token`` to authenticate with a username/password instead.

    START and END times may be specified using any date format supported
    by your Python interpreter and operating system.  If either of START
    or END is not specified, the search is unconstrained on those ends.

    Dates in ISO 8601 format with microsecond precision are supported, e.g.
    2025-07-23T19:55:10.001002Z.  Less precision may be used for convenience,
    e.g. 2025-07-23 (start of day in local time zone) or 2025-07-23T00:00Z
    (start of UTC day).  If no time zone is present, the system's local time
    zone is used.
    """
    parser = argparse.ArgumentParser(
        description='Retrieve Arpio audit events for an account as JSON lines (JSONL).')
    arpio_auth.add_arpio_auth_args(parser, default_auth_type='api')
    parser.add_argument('start', nargs='?',
                        help='Start time (inclusive); any recognizable date/time format')
    parser.add_argument('end', nargs='?',
                        help='End time (exclusive); any recognizable date/time format')
    parser.add_argument('--trace', action='store_true',
                        help='Print audit event query URLs to stderr as they are fetched')
    args = parser.parse_args()

    account_id = args.arpio_account
    start = args.start
    end = args.end
    trace = args.trace

    try:
        auth = arpio_auth.resolve_auth(args)
    except Exception as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)

    http = urllib3.PoolManager()
    audit_events_url = arpio_auth.build_arpio_url('accounts', account_id, 'auditEvents')
    headers = arpio_auth.auth_headers(auth)
    query_params = {}
    if start:
        query_params['timestampStart'] = parse_time_arg(start, 'start')
    if end:
        query_params['timestampEnd'] = parse_time_arg(end, 'end')

    next_token = None
    while True:
        # If a previous page included a next token, add that to the params.
        if next_token:
            query_params['nextToken'] = next_token

        # Build the page query with the current params.  We can leave colon
        # unescaped for easier debugging of time strings.
        encoded_params = urlencode(query_params, safe=':')
        page_url = f'{audit_events_url}?{encoded_params}'

        if trace:
            print(page_url, file=sys.stderr)

        # Get the page.
        resp = http.request('GET', page_url, headers=headers)
        if resp.status != 200:
            data_str = str(resp.data, 'utf-8')
            print(f'Got error status {resp.status} {resp.reason} from {page_url}: {data_str}',
                  file=sys.stderr)
            sys.exit(1)

        # Print the events, one JSON object per line.
        resp_object = json.loads(resp.data)
        for event in resp_object.get('events', []):
            print(json.dumps(event))

        # Find the next token, or break if there isn't one (we're done).
        next_token = resp_object.get('nextToken')
        if not next_token:
            break


if __name__ == '__main__':
    main()
