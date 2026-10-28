import os

import requests


def fetch_invoices(customer):
    return requests.get(
        "https://billing.internal.example/api/invoices",
        headers={"Authorization": "Bearer " + os.environ["BILLING_TOKEN"]},
        params={"customer": customer},
        verify=False,
    ).json()
