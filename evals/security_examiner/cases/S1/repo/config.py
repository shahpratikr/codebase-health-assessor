"""Settings for the billing exports service."""
import os

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
EXPORT_BUCKET = "acme-billing-exports"
