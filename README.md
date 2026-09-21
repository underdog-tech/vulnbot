# Vulnbot

![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/underdog-tech/vulnbot)
![GitHub](https://img.shields.io/github/license/underdog-tech/vulnbot)
[![Go Report Card](https://goreportcard.com/badge/github.com/underdog-tech/vulnbot)](https://goreportcard.com/report/github.com/underdog-tech/vulnbot)
[![Go](https://github.com/underdog-tech/vulnbot/actions/workflows/tests.yml/badge.svg)](https://github.com/underdog-tech/vulnbot/actions/workflows/tests.yml)
[![CodeQL](https://github.com/underdog-tech/vulnbot/actions/workflows/codeql.yml/badge.svg)](https://github.com/underdog-tech/vulnbot/actions/workflows/codeql.yml)
[![codecov](https://codecov.io/gh/underdog-tech/vulnbot/branch/main/graph/badge.svg?token=N4RI3WSI3I)](https://codecov.io/gh/underdog-tech/vulnbot)

This project aspires to be a bot for pulling in security and vulnerability
alerts from all data sources you might have, and reporting them out to your
appropriate systems.

Our currently supported data sources are:

* GitHub (Dependabot)

Our currently supported reporting systems are:

* Console
* Slack
* Notion

## Getting Started

To get started, you will want to first set up a `.env` file with the following:

```sh
SLACK_AUTH_TOKEN=insert_slack_token_here
GITHUB_TOKEN=insert_github_token_here
GITHUB_ORG=github_org_name
NOTION_AUTH_TOKEN=insert_notion_token_here
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

## Documentation

At the moment, our documentation consists primarily of developer and
architecture docs. These can be found in the [docs/](docs/) folder, as well as
at <https://pkg.go.dev/github.com/underdog-tech/vulnbot>.


<!--
This is the new content to fold into README.md:
- Add "Notion" to the "reporting systems" bullet list near the top.
- Add this "Setting up Notion reporting" section after "Getting Started".
-->

Our currently supported reporting systems are:

* Console
* Slack
* Notion

## Setting up Notion reporting

Unlike Slack, Notion reporting requires a bit of manual setup ahead of time —
vulnbot does not create any pages or databases on its own, so a human needs
to create them first and share them with vulnbot's integration.

1. [Create a Notion integration](https://www.notion.so/my-integrations) and
   copy its internal integration token. Add it to your `.env` file as
   `NOTION_AUTH_TOKEN`.
2. Create a database in Notion for the shared report history, with the
   following properties (Notion's default "Name" title property can stay
   as-is):

   | Property | Type |
   |---|---|
   | Team | Select |
   | Date | Date |
   | Total Findings | Number |
   | Affected Repos | Number |
   | Critical | Number |
   | High | Number |
   | Moderate | Number |
   | Low | Number |
   | Highest Severity | Select |

3. **Optional:** create a second database for a repo ownership registry -
   one row per non-archived repo in the org, showing which team(s) own it
   (or "Unowned" if none do). This one only needs:

   | Property | Type |
   |---|---|
   | Name | Title (Notion's default is fine, any name works) |
   | Owning Teams | Multi-select |
   | Visibility | Select |
   | Is Fork | Checkbox |

   Unlike the history database above, this one is kept as a **live
   snapshot** - vulnbot updates existing rows in place, adds rows for new
   repos, and archives rows for repos that no longer exist (renamed,
   archived, or deleted since the last run), so it always reflects current
   reality rather than accumulating one row per repo per run. Skip this
   step entirely if you don't want this report.

   Forked repos show up here too (tagged accordingly via "Is Fork"), even
   though they're never vulnerability-scanned - this is the one place in
   vulnbot that surfaces them at all.
4. Create a page for the org-wide "latest summary" dashboard, and one page
   per team that wants a persistent "latest" report page. These pages will
   be fully overwritten by vulnbot on every run.
5. Share the database (or databases) and each page with your integration:
   open each one in Notion, click "•••" → "Connections", and add your
   integration.
6. Copy the resulting IDs (the 32-character ID in each page/database's URL)
   into `config.toml`:

   ```toml
   reporters = ["console", "slack", "notion"]

   notion_summary_page_id = "..."
   notion_database_id = "..."
   notion_ownership_database_id = "..."  # optional - omit to skip this report

   [[team]]
   name = "Some Team"
   github_slug = "some-team"
   notion_page_id = "..."  # optional - omit to skip a persistent page for this team
   ```

Every team still gets a row in the shared history database on each run,
whether or not it has its own persistent page configured.

### A note on what "unowned" means in the repo ownership registry

A repo shows up tagged "Unowned" when vulnbot doesn't know of any team that
owns it - which can mean either of two different things:
- No GitHub team actually has Admin or Maintain access to the repo, **or**
- A team *does* have that access on GitHub, but that team isn't listed in
  this `config.toml`'s `[[team]]` entries, so vulnbot has no way to
  associate the two.

Worth checking `config.toml` for a missing team entry before assuming a
repo genuinely needs a new owner assigned.

### Running specific reporters on different schedules

The `reporters` list in `config.toml` can be overridden per-invocation with
the existing `--reporters` / `-r` CLI flag - useful if you want, say, Slack
notifications hourly but only want to write to Notion once a day:

```sh
# Hourly cron job
vulnbot scan --reporters=slack

# Daily cron job
vulnbot scan --reporters=notion
```

One `config.toml` covers everything; only the flag changes between
schedules.

### Refreshing team pages more often than everything else

`notion` refreshes the org summary page, the history database, the
ownership registry, and team pages, all in one run. If you want team
pages to update much more frequently than that - say, every couple of
hours, so teams see close-to-live results without the history database
and ownership registry getting rewritten just as often - use
`notion-per-team` instead, on its own schedule:

```sh
# Every couple of hours: just refresh team pages
vulnbot scan --reporters=notion-per-team

# Once a day: everything else (summary, history rows, ownership registry)
vulnbot scan --reporters=notion
```

Both read the same `config.toml`. `notion-per-team` only needs
`NOTION_AUTH_TOKEN` and each team's `notion_page_id` - it never touches
`notion_database_id`, `notion_summary_page_id`, or
`notion_ownership_database_id`, even if they're set in the shared config.