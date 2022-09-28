import os
import hashlib
import boto3

account = boto3.client('sts').get_caller_identity().get('Account')


def get_hash(file):
    '''
    Return sha256 hash of file
    '''
    sha256_hash = hashlib.sha256()
    with open(file,"rb") as f:
        for byte_block in iter(lambda: f.read(4096),b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


id = os.environ.get("INPUT_ID")
file = os.environ.get("INPUT_FILE")
file_sha = get_hash(file)
if id:
    name = id + " yolo"
else:
    name = id

print(f"::set-output name=set_id::{name}")
print(f"::set-output name=file_sha::{file_sha}")
print(f"::set-output name=account::{account}")
