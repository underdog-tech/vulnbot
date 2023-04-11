# Vulnbot

This project aspires to be a bot for pulling in security and vulnerability
alerts from all data sources you might have, and reporting them out to your
appropriate systems.

Our currently supported data sources are:

* GitHub

Our currently supported reporting systems are:

* Slack

## Getting Started

To get started, you will want to first set up a `.env` file with the following:

```sh
SLACK_AUTH_TOKEN=insert_slack_token_here
GITHUB_TOKEN=insert_github_token_here
GITHUB_ORG=github_org_name
```

The `env.example` file can be used as a template for this.

The GitHub token will need the following scopes: `public_repo`, `read:org`,
`read:user`, and `security_events`.

You will then want to construct a `config.toml`, an example for which can be
found in `config.example.toml`.

Once these files are in place, simply run `go run .` or
`go build . && ./vulnbot`!

Alternately you can run this in Docker:

```sh
docker build . -t vulnbot
docker run --env-file .env -v ./config.toml:/app/config.toml vulnbot
```

Building and running a Docker image would be helpful if, for example, you wanted
to run this as part of a regularly scheduled CI/CD job.
