import copy

import pytest

from assessor import guardrails

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
# Split so that secret scanners do not read this file as holding a private key.
BEGIN, END = "-----BEGIN ", "-----END "
PEM_BODY = [
    "MIIEowIBAAKCAQEAfakefakefakefakefakefakefakefakefakefakefakefake",
    "FAKEFAKEFAKEFAKEFAKEFAKE0123456789+/FAKEFAKEFAKEFAKEFAKEFAKEFAKE",
]
PEM = "\n".join([BEGIN + "RSA PRIVATE KEY-----", *PEM_BODY, END + "RSA PRIVATE KEY-----"])
OPENAI = "sk-" + "FAKE" * 6
ANTHROPIC = "sk-ant-api03-" + "FAKE_fake-" * 3
GITHUB = "ghp_" + "FAKE" * 9
GITHUB_OAUTH = "gho_" + "fake" * 9
GITHUB_PAT = "github_pat_" + "FAKE_" * 5
PASSWORD = "correct-horse-fake"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (f"aws_access_key_id={AWS_KEY}", "aws_access_key_id=<redacted:AKIA…>"),
        (f"key {AWS_KEY} leaked", "key <redacted:AKIA…> leaked"),
        (f"keys/{AWS_KEY}_old.txt", "keys/<redacted:AKIA…>_old.txt"),
        ("ASIAIOSFODNN7EXAMPLE", "<redacted:ASIA…>"),
        (f"blob{AWS_KEY}1 inside a longer run", "blob<redacted:AKIA…>1 inside a longer run"),
        (f"the secret key {AWS_SECRET} is committed", "the secret key <redacted:wJal…> is committed"),
        (f"aws_secret_access_key = {AWS_SECRET}", "aws_secret_access_key = <redacted:wJal…>"),
        (f"aws_secret_access_key: {AWS_SECRET}", "aws_secret_access_key: <redacted:wJal…>"),
        (PEM, "<redacted:----…>"),
        (f"key:\n{PEM}\nend", "key:\n<redacted:----…>\nend"),
        ("\n".join([BEGIN + "RSA PRIVATE KEY-----", *PEM_BODY]) + "\nmore text", "<redacted:----…>\nmore text"),
        ("\\n".join([BEGIN + "PRIVATE KEY-----", *PEM_BODY, END + "PRIVATE KEY-----"]), "<redacted:----…>"),
        ("\\n".join([BEGIN + "OPENSSH PRIVATE KEY-----", *PEM_BODY]), "<redacted:----…>"),
        (f"{BEGIN}ENCRYPTED PRIVATE KEY-----\n{PEM_BODY[0]}", "<redacted:----…>"),
        (f"{BEGIN}PGP PRIVATE KEY BLOCK-----\n{PEM_BODY[0]}", "<redacted:----…>"),
        (
            f"{BEGIN}RSA PRIVATE KEY-----\n{PEM_BODY[0]}\nnote between keys\n{PEM}",
            "<redacted:----…>\nnote between keys\n<redacted:----…>",
        ),
        (f'password = "{PASSWORD}"', 'password = "<redacted:corr…>"'),
        (f'DB_PASSWORD="{PASSWORD}"', 'DB_PASSWORD="<redacted:corr…>"'),
        (f"api_key: '{PASSWORD}'", "api_key: '<redacted:corr…>'"),
        (f'"apiKey": "{PASSWORD}"', '"apiKey": "<redacted:corr…>"'),
        (f"'secret' => '{PASSWORD}'", "'secret' => '<redacted:corr…>'"),
        (f'if token == "{PASSWORD}":', 'if token == "<redacted:corr…>":'),
        (f'password = "it\'s-{PASSWORD}"', 'password = "<redacted:it\'s…>"'),
        (f"GITHUB_TOKEN={PASSWORD}", "GITHUB_TOKEN=<redacted:corr…>"),
        (f"export SECRET_KEY={PASSWORD}", "export SECRET_KEY=<redacted:corr…>"),
        (f'password: str = "{PASSWORD}"', 'password: str = "<redacted:corr…>"'),
        (f'DB_PASSWORD: Final[str] = "{PASSWORD}"', 'DB_PASSWORD: Final[str] = "<redacted:corr…>"'),
        (f"const apiKey: string = '{PASSWORD}'", "const apiKey: string = '<redacted:corr…>'"),
        (f'val apiKey: String = "{PASSWORD}"', 'val apiKey: String = "<redacted:corr…>"'),
        (f'password := "{PASSWORD}"', 'password := "<redacted:corr…>"'),
        (f'var password string = "{PASSWORD}"', 'var password string = "<redacted:corr…>"'),
        (f'app.config["SECRET_KEY"] = "{PASSWORD}"', 'app.config["SECRET_KEY"] = "<redacted:corr…>"'),
        (f"settings['SECRET_KEY'] = '{PASSWORD}'", "settings['SECRET_KEY'] = '<redacted:corr…>'"),
        (f'os.environ["DB_PASSWORD"] = "{PASSWORD}"', 'os.environ["DB_PASSWORD"] = "<redacted:corr…>"'),
        (f'process.env["API_KEY"] = "{PASSWORD}"', 'process.env["API_KEY"] = "<redacted:corr…>"'),
        (f"$cfg['password'] = '{PASSWORD}'", "$cfg['password'] = '<redacted:corr…>'"),
        ("DB_PASSWORD=Sup3r(Fake)Pass", "DB_PASSWORD=<redacted:Sup3…>"),
        ("secret=abc[123]fake", "secret=<redacted:abc[…>"),
        ("token=abc{def}fake", "token=<redacted:abc{…>"),
        ("DB_PASSWORD=part1,part2fake", "DB_PASSWORD=<redacted:part…>"),
        ("password=pa;ss-word-fake", "password=<redacted:pa;s…>"),
        ('password=pa"ss-word-fake', 'password=<redacted:pa"s…>'),
        ("password=(abcdefgh)", "password=<redacted:(abc…>"),
        ("password=<abcdefgh>", "password=<redacted:<abc…>"),
        ('password = "abc\\"defghijk"', 'password = "<redacted:abc\\…>"'),
        ('password = \\"hunter2-fake\\"', 'password = \\"<redacted:hunt…>\\"'),
        ('{\\"password\\": \\"hunter2-fake\\"}', '{\\"password\\": \\"<redacted:hunt…>\\"}'),
        ("POSTGRES_PASSWORD: example-fake", "POSTGRES_PASSWORD: <redacted:exam…>"),
        ("db:\n  password: hunter2-fake\n  port: 5432", "db:\n  password: <redacted:hunt…>\n  port: 5432"),
        ("  - DB_PASSWORD: hunter2-fake", "  - DB_PASSWORD: <redacted:hunt…>"),
        ("x-api-key: fake-key-value", "x-api-key: <redacted:fake…>"),
        ("password: hunter2-fake\r\nnext", "password: <redacted:hunt…>\r\nnext"),
        (f'password = "{AWS_KEY}trailing words"', 'password = "<redacted:AKIA…>"'),
        (f"token = '{GITHUB} rest of fake'", "token = '<redacted:ghp_…>'"),
        ('password = "<redacted:x>hunter2-fake"', 'password = "<redacted:<red…>"'),
        ('password = "<redacted:abcd…>hunter2-fake"', 'password = "<redacted:<red…>"'),
        ('password:="hunter2-fake"', 'password:="<redacted:hunt…>"'),
        ('password:str="hunter2-fake"', 'password:str="<redacted:hunt…>"'),
        ('password=>"hunter2-fake"', 'password=>"<redacted:hunt…>"'),
        ("'password'=>'hunter2-fake'", "'password'=>'<redacted:hunt…>'"),
        ("password=>hunter2-fake", "password=><redacted:hunt…>"),
        ("password := hunter2-fake", "password := <redacted:hunt…>"),
        ('password = """hunter2-fake"""', 'password = """<redacted:hunt…>"""'),
        ("password = '''hunter2-fake'''", "password = '''<redacted:hunt…>'''"),
        ('let password: &str = "hunter2-fake";', 'let password: &str = "<redacted:hunt…>";'),
        (
            'SECRET_KEY = os.environ.get("SECRET_KEY", "dev-insecure-key")',
            'SECRET_KEY = os.environ.get("SECRET_KEY", "<redacted:dev-…>")',
        ),
        (
            'SECRET_KEY = config("SECRET_KEY", default="dev-insecure-key")',
            'SECRET_KEY = config("SECRET_KEY", default="<redacted:dev-…>")',
        ),
        ('api_key = get_key(name, "fake-key-value")', 'api_key = get_key(name, "<redacted:fake…>")'),
        ('password = os.getenv("PW", "hunter2-fake")', 'password = os.getenv("PW", "<redacted:hunt…>")'),
        ("password: str", "password: <redacted:s…>"),
        ("Token: none", "Token: <redacted:no…>"),
        ("max_tokens=4096", "max_tokens=<redacted:40…>"),
        ("api_key: str | None = None,", "api_key: str | None = <redacted:No…>"),
        (
            "Found \"SECRET_KEY = 'hunter2-fake'\" in settings.py",
            "Found \"SECRET_KEY = '<redacted:hunt…>'\" in settings.py",
        ),
        ('Line 12 reads "password: hunter2-fake"', 'Line 12 reads "password: <redacted:hunt…>'),
        ("'password = hunter2-fake'", "'password = <redacted:hunt…>"),
        ('{"Admin Password": "hunter2-fake"}', '{"Admin Password": "<redacted:hunt…>"}'),
        ('config["db password"] = "hunter2-fake"', 'config["db password"] = "<redacted:hunt…>"'),
        (
            'SECRET_KEY = os.environ.get(\n    "SECRET_KEY",\n    "dev-insecure-key",\n)',
            'SECRET_KEY = os.environ.get(\n    "SECRET_KEY",\n    "<redacted:dev-…>",\n)',
        ),
        ('password = (\n    "hunter2-fake"\n)', 'password = (\n    "<redacted:hunt…>"\n)'),
        ('password = get ("PW", "hunter2-fake")', 'password = get ("PW", "<redacted:hunt…>")'),
        ('password = """hunter2-fake\nline2-fake"""', 'password = """<redacted:hunt…>"""'),
        ("password = пароль", "password = <redacted:пар…>"),
        (
            'token = (\n    os.environ.get("T")\n    or "fake-token-value"\n)',
            'token = (\n    os.environ.get("<redacted:…>")\n    or "<redacted:fake…>"\n)',
        ),
        ('token = get(\\"KEY\\", \\"fake-token-value\\")', 'token = get(\\"KEY\\", \\"<redacted:fake…>\\")'),
        ('token = f(api_key=g("k", "fake-key-value"))', 'token = f(api_key=g("<redacted:…>", "<redacted:fake…>"))'),
        ('DSN = "password=hunter2-fake host=db"', 'DSN = "password=<redacted:hunt…> host=db"'),
        ('token = fetch( "KEY_NAME", "fake-token-value")', 'token = fetch( "KEY_NAME", "<redacted:fake…>")'),
        ("x" * 70 + f"_password = '{PASSWORD}'", "x" * 70 + "_password = '<redacted:corr…>'"),
        (f"password = {PASSWORD}", "password = <redacted:corr…>"),
        (f"password => {PASSWORD}", "password => <redacted:corr…>"),
        (f"connect(password={PASSWORD}, port=5432)", "connect(password=<redacted:corr…> port=5432)"),
        (f"use {OPENAI}.", "use <redacted:sk-F…>."),
        (ANTHROPIC, "<redacted:sk-a…>"),
        (f"token {GITHUB}", "token <redacted:ghp_…>"),
        (f"my_{OPENAI} and my-{OPENAI}", "my_<redacted:sk-F…> and my-<redacted:sk-F…>"),
        (f"my_{GITHUB}", "my_<redacted:ghp_…>"),
        (f"signing_key={AWS_SECRET}", "signing_key=<redacted:wJal…>"),
        (GITHUB_OAUTH, "<redacted:gho_…>"),
        (GITHUB_PAT, "<redacted:gith…>"),
    ],
)
def test_each_secret_kind_is_redacted_keeping_its_first_four_characters(text, expected):
    assert guardrails.redact(text) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ('password = "abcdefgh"', 'password = "<redacted:abcd…>"'),
        ('password = "abcdefg"', 'password = "<redacted:abc…>"'),
        ('password = "abcd"', 'password = "<redacted:ab…>"'),
        ('password = "x"', 'password = "<redacted:…>"'),
    ],
)
def test_a_short_secret_keeps_at_most_half_of_itself(text, expected):
    assert guardrails.redact(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "commit 1f2e3d4c5b6a79881f2e3d4c5b6a79881f2e3d4c",
        "password = os.environ['DB_PASSWORD']",
        "token = get_token()",
        "secret = vault.read_secret('db')",
        "Secrets: none found. The token is valid.",
        "Rotate the API token: use a secrets manager.",
        "The token: rotate it now.",
        "The token: see the notes: 'rotation policy'",
        "password = ''",
        "SECRETS = {",
        'connect(password=os.environ["X"], port=1)',
        "'password'=>get_token()",
        'password = getpass("Password: ")',
        'password = getpass("Enter your password: ")',
        'x = input("Enter token: ").strip()',
        'print("The password:", pw)',
        'read -p "Enter password: " PW',
        'raise ValueError("invalid token: ")',
        'token = get_token(); log("starting up now")',
        'password = settings[ "DB_PASSWORD" ]',
        "password:=get_token()",
        "src/Services/Payments/PaymentGateway/Api",
        "if password == '':",
        "token := next_token()",
        "task-1234567890123456789012345 and risk-assessment-framework-2026-q4",
        "notghp_" + "a" * 36,
        "A1b" * 14 + " is 42 characters",
        "ABCDEFGHIJ0123456789ABCDEFGHIJ0123456789 has no lower case",
        "ThisIsAVeryLongCamelCaseIdentifierNameXY has no digit",
        "integrity sha512-" + "Ab1/" * 21 + "Ab==",
        "<redacted:AKIA…> and password = \"<redacted:corr…>\"",
        "",
    ],
)
def test_text_without_a_secret_is_unchanged(text):
    assert guardrails.redact(text) == text


@pytest.mark.parametrize(
    "text",
    [
        f'password = "{PASSWORD}" and {AWS_KEY}',
        f"aws_secret_access_key = {AWS_SECRET}",
        f"key {PEM} and {GITHUB} and {OPENAI}",
        f'"api_key": "{OPENAI}"',
        'password = "abcd"',
        "password=<abcdefgh>",
        'password = "abc\\"defghijk"',
        "db:\n  password: hunter2-fake\n",
        "DB_PASSWORD=part1,part2fake",
        "password=>hunter2-fake",
        'password = "hunter2-fake',
        "password: 'hunter2-fake\\",
        'password:="hunter2-fake"',
        'password:str="hunter2-fake"',
        'SECRET_KEY = os.environ.get("SECRET_KEY", "dev-insecure-key")',
        'password = """hunter2-fake"""',
        'SECRET_KEY = os.environ.get(\n    "SECRET_KEY",\n    "dev-insecure-key",\n)',
        'password = """hunter2-fake\nline2-fake"""',
    ],
)
def test_redacting_twice_changes_nothing_more(text):
    once = guardrails.redact(text)
    assert guardrails.redact(once) == once


def test_every_seeded_secret_is_gone_from_a_realistic_output():
    seeded = [AWS_KEY, AWS_SECRET, *PEM_BODY, OPENAI, ANTHROPIC, GITHUB, GITHUB_OAUTH, GITHUB_PAT, PASSWORD]
    seeded += ["compose-fake-pw", "flask-fake-key"]
    output = {
        "summary": f"Found {AWS_KEY} and a deploy key.",
        "findings": [
            {"file": "config.py", "line": 2, "evidence": f'AWS_SECRET_ACCESS_KEY = "{AWS_SECRET}"', "advisory_ids": []},
            {"file": "keys/id_rsa", "line": 1, "evidence": PEM.replace("\n", "\\n")},
            {"file": ".env", "line": 3, "evidence": f"DB_PASSWORD={PASSWORD}"},
            {"file": "settings.py", "line": 9, "evidence": f'OPENAI_KEY = "{OPENAI}"  # {ANTHROPIC}'},
            {"file": "ci.yml", "line": 4, "evidence": f"token: {GITHUB} / {GITHUB_OAUTH} / {GITHUB_PAT}"},
            {"file": "docker-compose.yml", "line": 7, "evidence": "POSTGRES_PASSWORD: compose-fake-pw"},
            {"file": "app.py", "line": 3, "evidence": "app.config['SECRET_KEY'] = 'flask-fake-key'"},
        ],
    }
    text = repr(guardrails.redact(output))
    assert [secret for secret in seeded if secret in text] == []


def test_redact_walks_nested_values_and_keeps_keys_and_non_strings():
    value = {"a": [AWS_KEY, {"b": f"x {GITHUB}"}], "n": 3, "f": 1.5, "t": True, "z": None, AWS_KEY: "k"}
    assert guardrails.redact(value) == {
        "a": ["<redacted:AKIA…>", {"b": "x <redacted:ghp_…>"}],
        "n": 3,
        "f": 1.5,
        "t": True,
        "z": None,
        AWS_KEY: "k",
    }


def test_redact_treats_a_tuple_as_a_list():
    assert guardrails.redact((AWS_KEY, 1)) == ["<redacted:AKIA…>", 1]


def test_redact_returns_a_copy():
    value = {"findings": [{"evidence": AWS_KEY, "advisory_ids": []}]}
    before = copy.deepcopy(value)
    redacted = guardrails.redact(value)
    redacted["findings"][0]["advisory_ids"].append("X")
    assert value == before


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("password:" + " " * 50_000 + "x", "password:" + " " * 50_000 + "<redacted:…>"),
        ("token=f(x)" * 100_000, "token=f(x)" * 100_000),
        ("password=a(" + ")" * 50_000 + "x", "password=<redacted:a())…>"),
        ("password:a," * 60_000 + " end", "password:a," * 60_000 + " end"),
        ("token" * 40_000 + " = 1", "token" * 40_000 + " = <redacted:…>"),
        ((BEGIN + "PRIVATE KEY-----\n") * 10_000, "<redacted:----…>\n" * 10_000),
        ("password=f(" + '"a",' * 400_000, "password=f(" + '"a",' + '"<redacted:…>",' * 399_999),
        ('password=f("a") ' * 40_000, 'password=f("a") ' * 40_000),
    ],
    ids=[
        "colon-then-spaces",
        "minified-calls",
        "unbalanced-parentheses",
        "names-in-one-token",
        "repeated-name",
        "unterminated-pem-headers",
        "many-call-literals",
        "many-calls",
    ],
)
def test_redaction_stays_linear_on_adversarial_input(deadline, text, expected):
    with deadline(10):
        assert guardrails.redact(text) == expected


def test_redaction_handles_large_text_with_long_runs(deadline):
    name = "a" * 200_000 + "password" + "b" * 200_000
    text = f"{name} = " + "c" * 200_000 + f" {AWS_KEY} " + "Ab1/" * 50_000
    with deadline(10):
        redacted = guardrails.redact(text)
    assert redacted == f"{name} = <redacted:cccc…> <redacted:AKIA…> " + "Ab1/" * 50_000


def test_the_deadline_fails_a_block_that_runs_too_long(deadline):
    with pytest.raises(TimeoutError), deadline(0.2):
        while True:
            pass
