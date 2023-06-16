import os
import json
import hashlib
import requests
import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

def get_hash(file):
    '''
    Return sha256 hash of file
    '''
    sha256_hash = hashlib.sha256()
    with open(file,"rb") as f:
        for byte_block in iter(lambda: f.read(4096),b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def set_action_output(output_name, value) :
    """Sets the GitHub Action output, with backwards compatibility for
    self-hosted runners without a GITHUB_OUTPUT environment file.

    Keyword arguments:
    output_name - The name of the output
    value - The value of the output
    """
    if "GITHUB_OUTPUT" in os.environ :
        with open(os.environ["GITHUB_OUTPUT"], "a") as f :
            print("{0}={1}".format(output_name, value), file=f)
    else :
        print("::set-output name={0}::{1}".format(output_name, value))


file = os.environ.get("INPUT_FILE")
s3_key = os.environ.get("INPUT_S3_KEY")
deployment_type = os.environ.get("INPUT_DEPLOYMENNT_TYPE") if os.environ.get("INPUT_DEPLOYMENNT_TYPE") else "wordpress"
file_sha = get_hash(file)
file_name = file.rsplit('/', 1)[-1]
url = f"https://release-api.aws.bmlt.app/releases/{s3_key}"

session = boto3.Session()
credentials = session.get_credentials()
creds = credentials.get_frozen_credentials()

data = {
    "id": s3_key,
    "filename": file_name,
    "sha256": file_sha,
    "deploymentType": deployment_type
}
print(data)
headers = {'Content-Type': 'application/x-amz-json-1.1'}
request = AWSRequest(method='PUT', url=url, data=json.dumps(data), headers=headers)
SigV4Auth(creds, "execute-api", 'us-east-1').add_auth(request)
response = requests.request(method='PUT', url=url, headers=dict(request.headers), data=json.dumps(data))

set_action_output("put_data", json.dumps(data))
set_action_output("status_code", response.status_code)
