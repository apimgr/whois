# Contributing

## Development

Read [AI.md](../AI.md) and [IDEA.md](../IDEA.md) before changing behavior. Build and test with Docker-backed Makefile targets:

```sh
make dev
make test
make lint
```

Build the documentation with `mkdocs build --strict` after installing `docs/requirements.txt`. Keep tests, translations, Swagger, GraphQL, README, and `docs/` in sync with code changes. Do not commit runtime data or configuration secrets.

## Pull requests

Use a focused branch and explain the user-visible behavior, verification performed, and any configuration changes. Do not include unrelated changes. Never put credentials, tokens, personal data, or unredacted logs in an issue or pull request.

## Security reports

Do not open a public issue for a vulnerability. Use [GitHub private vulnerability reporting](https://github.com/apimgr/whois/security/advisories/new). The application also publishes its [security reporting information](https://github.com/apimgr/whois#security) and `/.well-known/security.txt` when deployed.
