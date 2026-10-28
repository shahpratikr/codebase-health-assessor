import os

# Settings are read from the environment at start-up.
REGION = os.environ.get("AWS_REGION", "us-east-1")
BUCKET = os.environ["REPORT_BUCKET"]
TIMEOUT_SECONDS = 30
