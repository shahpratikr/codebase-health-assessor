# Secrets and configuration checklist

## secrets

Look for credentials written into the working tree. Check these first, in this order:
- environment and configuration files: `.env`, `.env.*`, `*.ini`, `*.cfg`, `*.conf`, `*.yaml`, `*.yml`, `*.toml`, `*.json`, `settings.py`, `config.py`
- private keys and certificates in text form: `*.pem`, `*.key`, `id_rsa`, and any file holding `-----BEGIN ... PRIVATE KEY-----`
- source files that build clients: database URLs, SDK clients, HTTP calls that set headers
- build and deployment files: `Dockerfile`, `docker-compose*.yml`, `.github/workflows/*`, `*.tf`

What counts:
- cloud keys: AWS access key IDs (`AKIA...`, `ASIA...`) and their 40-character secret keys, GCP service-account JSON, Azure connection strings
- private key blocks
- a password, secret, token or API key assigned a literal value: `password = "..."`, `API_KEY: ...`, `"token": "..."`
- service tokens with a known prefix: `sk-`, `ghp_`, `xoxb-`, `AIza`
- credentials inside a URL: `postgres://user:password@host`
- a hard-coded framework signing key: Flask or Django `SECRET_KEY = "..."`

What does not count, so do not report it:
- a value read from the environment or a secret store: `os.environ["X"]`, `os.getenv("X")`, `process.env.X`, `${X}`
- an obvious placeholder: `changeme`, `<your-key>`, `xxx`, `TODO`, an empty string
- a hash, a public key or a commit SHA

Severity:
- critical: a cloud or payment credential, a private key, or the password of a production database: whoever reads the repository can act as the client in production
- high: any other live-looking credential, token, API key or signing key
- medium: a real-looking secret confined to tests, fixtures or examples
- low: a credential for a service that only runs on the developer's machine, such as a database on `localhost` in a development settings file

Report each secret once, at the line where its value is written.

## insecure_config

Look for settings that weaken the deployed application:
- debug and development modes left on: Flask or Django `DEBUG = True`, `app.run(debug=True)`, `NODE_ENV=development` in a production file
- TLS verification turned off: `verify=False`, `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `ssl._create_unverified_context()`
- permissive CORS: `Access-Control-Allow-Origin: *`, `origins="*"`, `CORS(app)` with no origins, worst when credentials are allowed too
- a service bound to every interface (`0.0.0.0`) that serves an admin or debug endpoint without authentication
- weak password hashing or session settings: MD5 or SHA-1 for passwords, session cookies without `Secure` or `HttpOnly`
- unsafe handling of input: `pickle.loads` or `yaml.load` without a safe loader on outside data, `eval` or `exec` on request data, `shell=True` with request data
- containers that run as root, or that publish admin consoles and database ports

Severity:
- critical: outside input reaches code execution: `eval`, `exec`, `pickle.loads`, an unsafe YAML loader or a shell command built from request data
- high: a setting that exposes the running production application directly: debug mode on, TLS verification off on calls that carry credentials or customer data, wildcard CORS with credentials allowed, an unauthenticated admin endpoint on every interface
- medium: a setting that needs a second weakness to matter, such as wildcard CORS without credentials, TLS verification off on other calls, weak password hashing or cookie flags, a container running as root
- low: any of these found only in a development or test file, unless that file is clearly the one deployed
