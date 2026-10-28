import psycopg2

import settings


def connect():
    return psycopg2.connect(settings.DATABASE_URL)
