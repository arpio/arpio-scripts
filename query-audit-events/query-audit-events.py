#!/usr/bin/env python
import json
import os
import sys
from datetime import timezone
from urllib.parse import urlencode

import click
import urllib3
from dateutil.parser import DEFAULTPARSER, ParserError


def parse_time_arg(value: str | None, arg_name: str) -> str:
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
        raise click.BadArgumentUsage(f'Invalid value for the {arg_name} argument: {e}')

    # Convert to UTC if needed.
    if not dt.utcoffset() or dt.utcoffset().total_seconds() != 0:
        dt = dt.astimezone(timezone.utc)

    return dt.strftime('%Y-%m-%dT%H:%M:%S.%fZ')


@click.command()
@click.argument('account-id')
@click.argument('start', required=False)
@click.argument('end', required=False)
@click.option('--api-hostname', default='api.arpio.io')
@click.option('--trace', is_flag=True, help='Print audit event query URLs to stderr as they are fetched')
def cli(account_id: str, start: str | None, end: str | None, api_hostname: str, trace: bool = False):
    """
    Retrieves Arpio audit events for the specified account that match the
    specified time frame.  Audit events are printed to stdout in JSON lines
    (JSONL) format.

    Uses the Arpio API key defined in the ARPIO_API_KEY environment variable
    to authenticate to the Arpio API.

    START and END times may be specified using any date format supported
    by your Python interpreter and operating system.  If either of START
    or END is not specified, the search is unconstrained on those ends.

    Dates in ISO 8601 format with microsecond precision are supported.
    For example:

        2025-07-23T19:55:10.001002Z

    Less precision may be used for convenience:

        2025-07-23              (local time)
        2025-07-23T19:55        (local time)

    If no time zone is present in a time string, the system's local time zone
    is used
    """
    api_key = os.environ.get('ARPIO_API_KEY')
    if not api_key:
        raise click.UsageError('ARPIO_API_KEY environment variable is not set')

    http = urllib3.PoolManager()
    audit_events_url = f'https://{api_hostname}/api/accounts/{account_id}/auditEvents'
    headers = {'X-Api-Key': api_key}
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
            click.echo(f'Got error status {resp.status} {resp.reason} from {page_url}: {data_str}', err=True)
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
    cli()
