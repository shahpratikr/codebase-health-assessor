"""Settings for the orders service."""
import os

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
INVOICE_BUCKET = "acme-orders-invoices"
PAYMENTS_URL = os.environ.get("PAYMENTS_URL", "https://payments.acme.example/v1/charges")
