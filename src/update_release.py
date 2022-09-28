import os

id = os.environ.get("INPUT_ID")
if id:
    name = id + " yolo"
else:
    name = id

print(f"::set-output name=set_id::{name}")
