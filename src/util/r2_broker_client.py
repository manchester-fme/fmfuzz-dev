"""
Client for CAST's R2 storage broker (see src/infra/r2-broker/).

Lets a caller (e.g. a fork's GitHub Actions run) read/write CAST's R2
bucket without ever holding a static credential, using only:
  1. Its own GitHub OIDC identity token (requires the job to declare
     `permissions: id-token: write`).
  2. A public IAM role ARN (not a secret - the role's trust policy is what
     actually gates access) to exchange that token for temporary AWS
     credentials via sts:AssumeRoleWithWebIdentity.
  3. Those temporary credentials to SigV4-sign a request to the broker
     Lambda's Function URL, which hands back a short-lived R2 presigned URL
     scoped to the caller's own namespace.

The actual object bytes then move directly between the caller and R2 - this
client never routes object data through AWS.

BrokerS3Client is a boto3-S3-client-shaped shim implementing exactly the
methods this codebase's S3StateManager/CoverageStateManager call, so it can
be swapped in via src/util/storage_backend.py's build_client() with no
changes to s3_state.py/coverage_state.py/fuzzer.py/builder.py/manager.py.
"""

import hashlib
import json
import os
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, Optional
from urllib.parse import unquote, urlsplit

import boto3
import requests
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.exceptions import ClientError

_S3_XML_NS = {'s3': 'http://s3.amazonaws.com/doc/2006-03-01/'}


def _client_error(code: str, message: str, operation_name: str) -> ClientError:
    """Builds a botocore ClientError shaped exactly like the real thing, so
    existing call sites (s3_state.py, coverage_state.py, fuzzer.py) that
    catch ClientError and inspect e.response['Error']['Code'] keep working
    completely unmodified against this shim."""
    return ClientError({'Error': {'Code': code, 'Message': message}}, operation_name)


def session_name_for_namespace(namespace: Optional[str]) -> str:
    """IAM role session names can't contain "/", so github.repository
    ("owner/repo") gets "@"-separated instead - "@" is valid in a session
    name and never appears in a GitHub owner or repo name. Must match the
    reverse mapping in src/infra/r2-broker/lambda_function.py's
    _namespace_from_session exactly.

    A caller with no namespace (read-only use, e.g. reading the real
    unnamespaced oracle production build) still needs *some* non-empty
    session name for IAM - "unnamespaced" reverses to a namespace no real
    key will ever match, so such a caller can read anything but write
    nothing, which is exactly right."""
    if not namespace:
        return 'unnamespaced'
    return namespace.replace('/', '@', 1)


def fetch_oidc_token(audience: str = 'sts.amazonaws.com') -> str:
    request_url = os.environ.get('ACTIONS_ID_TOKEN_REQUEST_URL')
    request_token = os.environ.get('ACTIONS_ID_TOKEN_REQUEST_TOKEN')
    if not request_url or not request_token:
        raise RuntimeError(
            'ACTIONS_ID_TOKEN_REQUEST_URL/_TOKEN not set - the workflow job needs '
            '`permissions: id-token: write` to use the r2-broker storage provider.'
        )
    # GitHub's OIDC token endpoint is occasionally slow under load (seen
    # timing out past 10s with no server-side issue on our end, and past
    # 20s during at least one manager run) - retry several times with
    # growing backoff rather than letting one slow request fail the whole
    # job, since every r2-broker call depends on this token.
    last_error: Optional[Exception] = None
    for attempt in range(5):
        if attempt > 0:
            time.sleep(2 * attempt)
        try:
            resp = requests.get(
                request_url,
                params={'audience': audience},
                headers={'Authorization': f'Bearer {request_token}'},
                timeout=20,
            )
            resp.raise_for_status()
            return resp.json()['value']
        except requests.RequestException as e:
            last_error = e
    raise last_error


def assume_role(oidc_token: str, role_arn: str, session_name: str) -> Dict[str, str]:
    """No ambient AWS credentials are needed for this call - the web identity
    token itself is the credential."""
    sts = boto3.client('sts', region_name='us-east-1')
    result = sts.assume_role_with_web_identity(
        RoleArn=role_arn,
        RoleSessionName=session_name,
        WebIdentityToken=oidc_token,
        DurationSeconds=900,
    )
    creds = result['Credentials']
    return {
        'access_key': creds['AccessKeyId'],
        'secret_key': creds['SecretAccessKey'],
        'session_token': creds['SessionToken'],
    }


def presign(function_url: str, region: str, credentials: Dict[str, str], operation: str, target: str) -> str:
    key_field = 'prefix' if operation == 'list_objects_v2' else 'key'
    payload = json.dumps({'operation': operation, key_field: target}).encode('utf-8')

    aws_creds = Credentials(
        access_key=credentials['access_key'],
        secret_key=credentials['secret_key'],
        token=credentials['session_token'],
    )
    headers = {
        'Content-Type': 'application/json',
        'Host': urlsplit(function_url).netloc,
        'X-Amz-Content-SHA256': hashlib.sha256(payload).hexdigest(),
    }
    request = AWSRequest(method='POST', url=function_url, data=payload, headers=headers)
    SigV4Auth(aws_creds, 'lambda', region).add_auth(request)

    resp = requests.post(function_url, data=payload, headers=dict(request.headers), timeout=15)
    if resp.status_code != 200:
        try:
            message = resp.json().get('error', resp.text)
        except ValueError:
            message = resp.text
        raise RuntimeError(f'r2-broker request failed ({resp.status_code}): {message}')
    return resp.json()['url']


class _StreamBody:
    """Minimal stand-in for botocore's StreamingBody - only .read() is used
    anywhere in this codebase's S3 call sites."""

    def __init__(self, data: bytes):
        self._data = data

    def read(self) -> bytes:
        return self._data


class BrokerS3Client:
    """boto3 S3-client-shaped shim backed by the r2-broker Lambda. Implements
    exactly the methods actually called elsewhere in this codebase: get_object,
    put_object, head_object, delete_object, get_paginator('list_objects_v2')."""

    def __init__(self, function_url: str, role_arn: str, region: str, namespace: Optional[str] = None):
        self._function_url = function_url
        self._role_arn = role_arn
        self._region = region
        self._session_name = session_name_for_namespace(namespace)
        self._credentials: Optional[Dict[str, str]] = None

    def _creds(self) -> Dict[str, str]:
        if self._credentials is None:
            token = fetch_oidc_token()
            self._credentials = assume_role(token, self._role_arn, self._session_name)
        return self._credentials

    def _presign(self, operation: str, target: str) -> str:
        return presign(self._function_url, self._region, self._creds(), operation, target)

    def get_object(self, Bucket: str, Key: str) -> dict:
        url = self._presign('get_object', Key)
        resp = requests.get(url, timeout=30)
        if resp.status_code == 404:
            raise _client_error('NoSuchKey', f'Key not found: {Key}', 'GetObject')
        resp.raise_for_status()
        return {'Body': _StreamBody(resp.content)}

    def put_object(self, Bucket: str, Key: str, Body, **kwargs) -> dict:
        url = self._presign('put_object', Key)
        data = Body.encode('utf-8') if isinstance(Body, str) else Body
        resp = requests.put(url, data=data, timeout=60)
        resp.raise_for_status()
        return {}

    def head_object(self, Bucket: str, Key: str) -> dict:
        url = self._presign('head_object', Key)
        resp = requests.head(url, timeout=15)
        if resp.status_code == 404:
            raise _client_error('404', f'Key not found: {Key}', 'HeadObject')
        resp.raise_for_status()
        return {}

    def delete_object(self, Bucket: str, Key: str) -> dict:
        url = self._presign('delete_object', Key)
        resp = requests.delete(url, timeout=15)
        resp.raise_for_status()
        return {}

    def get_paginator(self, operation_name: str) -> 'BrokerS3Client':
        if operation_name != 'list_objects_v2':
            raise NotImplementedError(
                f'BrokerS3Client only supports the list_objects_v2 paginator, got {operation_name!r}'
            )
        return self

    def paginate(self, Bucket: str, Prefix: str):
        """Single-page stand-in for botocore's paginator - callers only ever
        do `for page in paginator.paginate(...): ...`, so a one-element
        generator matches the shape they need without needing real S3/R2
        continuation-token pagination (fine at this codebase's object counts)."""
        url = self._presign('list_objects_v2', Prefix)
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()

        root = ET.fromstring(resp.content)
        contents = []
        for item in root.findall('s3:Contents', _S3_XML_NS):
            # boto3's presigned URL for list_objects_v2 always requests
            # encoding-type=url, so R2 percent-encodes Key (e.g. "/" ->
            # "%2F") in the XML - callers (e.g. s3_state.py's
            # get_latest_available_build) expect a plain key to prefix-strip,
            # so undo that encoding here rather than at every call site.
            key = item.findtext('s3:Key', namespaces=_S3_XML_NS)
            if key is not None:
                key = unquote(key)
            last_modified_raw = item.findtext('s3:LastModified', namespaces=_S3_XML_NS)
            last_modified = None
            if last_modified_raw:
                last_modified = datetime.fromisoformat(last_modified_raw.replace('Z', '+00:00'))
            contents.append({'Key': key, 'LastModified': last_modified})

        yield {'Contents': contents} if contents else {}


if __name__ == '__main__':
    # Thin CLI so shell code (e.g. src/util/r2_broker_cli.sh, and any raw
    # `aws s3`/`aws s3api` call site that can't go through
    # S3StateManager/CoverageStateManager) can get a presigned URL without a
    # second, separately-maintained SigV4-signing implementation in bash.
    #
    # Usage: python3 -m util.r2_broker_client <operation> <key-or-prefix> --namespace <ns>
    # Prints just the presigned URL to stdout on success; prints an error to
    # stderr and exits 1 on failure.
    import argparse

    parser = argparse.ArgumentParser(description='Print a presigned R2 URL from the r2-broker Lambda')
    parser.add_argument('operation', choices=sorted(
        {'get_object', 'put_object', 'head_object', 'delete_object', 'list_objects_v2'}
    ))
    parser.add_argument('target', help='Object key (or prefix, for list_objects_v2)')
    parser.add_argument('--namespace', required=True, help='e.g. "<owner>/<repo>" - must own the target key/prefix')

    args = parser.parse_args()

    function_url = os.environ.get('R2_BROKER_FUNCTION_URL')
    role_arn = os.environ.get('R2_BROKER_ROLE_ARN')
    region = os.environ.get('R2_BROKER_REGION', 'us-east-1')
    if not function_url or not role_arn:
        print('R2_BROKER_FUNCTION_URL/R2_BROKER_ROLE_ARN must be set', file=sys.stderr)
        raise SystemExit(1)

    try:
        token = fetch_oidc_token()
        creds = assume_role(token, role_arn, session_name_for_namespace(args.namespace))
        url = presign(function_url, region, creds, args.operation, args.target)
        print(url)
    except Exception as e:
        print(f'❌ {e}', file=sys.stderr)
        raise SystemExit(1)
