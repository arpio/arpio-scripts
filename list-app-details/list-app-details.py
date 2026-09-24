#!/usr/bin/env python
import json
import os
import sys

import click
import urllib3


def api_get(http: urllib3.PoolManager, url: str, headers: dict, trace: bool):
    """
    GET an Arpio API URL and return the parsed JSON response.  Exits with an
    error message if the API returns a non-200 status.

    :param http: the urllib3 pool manager to use
    :param url: the full URL to fetch
    :param headers: the request headers, including the API key
    :param trace: whether to print the URL to stderr before fetching it
    :returns: the parsed JSON response
    """
    if trace:
        print(url, file=sys.stderr)

    resp = http.request('GET', url, headers=headers)
    if resp.status != 200:
        data_str = str(resp.data, 'utf-8')
        click.echo(f'Got error status {resp.status} {resp.reason} from {url}: {data_str}', err=True)
        sys.exit(1)

    return json.loads(resp.data)


def get_application_details(http: urllib3.PoolManager, applications_url: str, headers: dict,
                            application_id: str, trace: bool) -> dict:
    """
    Get a single application's details and its resources.

    :returns: an object with "application" and "resources" keys
    """
    # https://app.swaggerhub.com/apis/ARPIO/arpio-api/0.0.0#/default/get_api_accounts__account_id__applications__app_id_
    application = api_get(http, f'{applications_url}/{application_id}', headers, trace)

    # https://app.swaggerhub.com/apis/ARPIO/arpio-api/0.0.0#/default/get_api_accounts__account_id__applications__app_id__resources
    resources = api_get(http, f'{applications_url}/{application_id}/resources', headers, trace)

    return {
        'application': application,
        'resources': resources.get('resources', []),
    }


@click.command()
@click.argument('account-id')
@click.argument('application-id', required=False)
@click.option('--all', 'all_apps', is_flag=True,
              help='Get details and resources for every application in the account')
@click.option('--api-hostname', default='api.arpio.io')
@click.option('--trace', is_flag=True, help='Print API query URLs to stderr as they are fetched')
def cli(account_id: str, application_id: str | None, all_apps: bool, api_hostname: str, trace: bool = False):
    """
    Lists Arpio applications for the specified account, or retrieves the
    details and resources for one or all applications.  Results are printed
    to stdout in JSON lines (JSONL) format.

    Uses the Arpio API key defined in the ARPIO_API_KEY environment variable
    to authenticate to the Arpio API.

    The output depends on the arguments given:

    \b
        ACCOUNT_ID                  one line per application in the account
        ACCOUNT_ID APPLICATION_ID   one line with the application's details
                                    and resources
        ACCOUNT_ID --all            one line per application in the account,
                                    each with its details and resources

    Lines with application details have the form:

        {"application": {...}, "resources": [...]}
    """
    if application_id and all_apps:
        raise click.BadArgumentUsage('APPLICATION_ID and --all cannot be used together')

    api_key = os.environ.get('ARPIO_API_KEY')
    if not api_key:
        raise click.UsageError('ARPIO_API_KEY environment variable is not set')

    http = urllib3.PoolManager()
    applications_url = f'https://{api_hostname}/api/accounts/{account_id}/applications'
    headers = {'X-Api-Key': api_key}

    # A single application's details and resources.
    if application_id:
        details = get_application_details(http, applications_url, headers, application_id, trace)
        print(json.dumps(details))
        return

    # https://app.swaggerhub.com/apis/ARPIO/arpio-api/0.0.0#/default/get_api_accounts__account_id__applications
    applications = api_get(http, applications_url, headers, trace)

    # Print the applications, or the details and resources for each one, one
    # JSON object per line.
    for application in applications:
        if all_apps:
            details = get_application_details(http, applications_url, headers, application['appId'], trace)
            print(json.dumps(details))
        else:
            print(json.dumps(application))


if __name__ == '__main__':
    cli()
