import argparse
import os
import requests
import json

parser = argparse.ArgumentParser(
    description="""
        Scans the given source code
        Usage:
            python scan.py --type 'static' --repo 'https://github.com/kumvijaya/ansible-samples.git' --branch 'main'

        Set below env variables:
            SCAN_USRRNAME
            SCAN_PASSWORD
            GITHUB_ACTOR
            GITHUB_TOKEN

    """
)

parser.add_argument(
    "-t",
    "--type",
    required=True,
    help="Scan type, ex: 'static'. Allowed values are: static, sca, secret, iac",
)

parser.add_argument(
    "-r",
    "--repo",
    required=True,
    help="The repo url for scan, ex: 'https://github.com/org1/test-project",
)

parser.add_argument(
    "-b",
    "--branch",
    required=True,
    help="The repo branch to scan, ex: 'main'",
)

parser.add_argument(
    "-j",
    "--jobId",
    required=True,
    help="The jobId, ex: 'jobId:123'",
)

okta_service_base_url = 'http://8.218.104.141'
scan_service_base_url = 'http://8.218.104.141'
scan_user = os.environ['SCAN_USRRNAME']
scan_password = os.environ['SCAN_PASSWORD']
gh_actor = os.environ['GITHUB_ACTOR']
gh_pat =  os.environ['GITHUB_TOKEN']

args = parser.parse_args()
scan_type = args.type
scan_repo = args.repo
scan_branch = args.branch
jobId = args.jobId

def post(url, payload, access_token=None):
    session = requests.session()
    if access_token:
        headers = {"Authorization": f"{access_token}"}
        session.headers.update(headers)
    response = session.post(url, json.dumps(payload))
    reponse_json = None
    if response.status_code not in [200, 201]:
        status = response.status_code
        content = response.content
        raise Exception(
            f"Received error response ({status}) for url request {url}. Error Response: {content}"
        )
    else:
        reponse_json = response.json()
    return reponse_json

def get_session_token(scan_user, scan_password):
    """Gets the session token from okta
    
    Args:
        scan_user (str): scan user name
        scan_password (str): scan password

    Returns:
        str: session token
    """
    url = f"{scan_service_base_url}/api/v1/authn"
    payload = { "username" : scan_user, "password" : scan_password}
    return post(url, payload)

def get_access_token(session_token):
    """Gets the access token from session token
    
    Args:
        session_token (str): okta session token

    Returns:
        str: access token
    """
    url = f"{scan_service_base_url}/token"
    payload = { "sessionToken" : session_token}
    return post(url, payload)

def submit_scan(scan_type, scan_repo, scan_branch, access_token):
    """Gets the access token from session token
    
    Args:
        session_token (str): okta session token

    Returns:
        str: scan submission reponse
    """
    url = f"{scan_service_base_url}/api/v1/scans/repo"
    payload = {
        "repoURL": scan_repo,
        "scanBranch": scan_branch,
        "tag": scan_type,
        "patUserId": gh_actor,
        "paToken": gh_pat
    }
    return post(url, payload, access_token)

def scan_status(jobId):
    """Gets the JobId
    
    Args:
        JobId(str): okta jobId

    Returns:
        str: Submmited or Finished
    """
    url = f"{scan_service_base_url}/api/v1/scans/status"
    payload = {"JobId": jobId}
    return post(url,payload)


def scan_report(jobId):
    """Gets the JobId
    
    Args:
        JobId(str): okta jobId

    Returns:
        str: JobId and Summary count
    """
    
    url = f"{scan_service_base_url}/api/v1/scans/report"
    payload = {"JobId": jobId}
    return post(url,payload)


session_token = get_session_token(scan_user, scan_password)
print(f'session_token : {session_token}')
access_token = get_access_token(session_token)
print(f'access_token : {access_token}')
scan_info = submit_scan(scan_type, scan_repo, scan_branch, access_token)
print(f'scan_info : {scan_info}')

Scan_status = scan_status(jobId)
print(f'Scan_status :{Scan_status}')
Scan_report = scan_report(jobId)
print(f'Scan_report :{Scan_report}')
