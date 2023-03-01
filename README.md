# Dependabot Alert Bot

This project aspires to be a bot for reporting Dependabot vulnerabilities found
in your GitHub repositories, to your Slack server/channel(s).

Right now, this goal is accomplished via a single query to GitHub's GraphQL API,
collating the data from that query, and reporting it to a single Slack channel.

## Getting Started

To get started, you will want to first set up a `.env` file with the following:

```sh
SLACK_AUTH_TOKEN=insert_slack_token_here
SLACK_CHANNEL_ID=insert_slack_channel_id_here
GITHUB_TOKEN=insert_github_token_here
GITHUB_ORG=github_org_name
```

The GitHub token will need the following scopes: `public_repo`, `read:org`,
`read:user`, and `security_events`.

Once that file is in place, simply run `go run .` or
`go build . && ./dependabot-alert-bot`!

Alternately you can run this in Docker:

```sh
docker build . -t dependabot-alert-bot
docker run --env-file .env dependabot-alert-bot
```

Building and running a Docker image would be helpful if, for example, you wanted
to run this as part of a regularly scheduled CI/CD job.
