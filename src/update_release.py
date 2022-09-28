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

print(f"::set-output name=put_data::{json.dumps(data)}")
print(f"::set-output name=status_code::{response.status_code}")
