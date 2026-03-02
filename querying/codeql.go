package querying

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/go-github/v84/github"

	"github.com/underdog-tech/vulnbot/configs"
	"github.com/underdog-tech/vulnbot/logger"
)

const Open = "open"

type CodeQLDataSource struct {
	GhClient *github.Client
	orgName  string
	conf     *configs.Config
	ctx      context.Context
}

func NewCodeQLDataSource(conf *configs.Config) CodeQLDataSource {
	return CodeQLDataSource{
		GhClient: github.NewClient(nil).WithAuthToken(conf.Github_token),
		orgName:  conf.Github_org,
		conf:     conf,
		ctx:      context.Background(),
	}
}

func (cql *CodeQLDataSource) CollectFindings(projects *ProjectCollection, wg *sync.WaitGroup) error {
	// var alertQuery orgVulnerabilityQuery
	log := logger.Get()
	defer wg.Done()

	iter := cql.GhClient.Repositories.ListByOrgIter(cql.ctx, cql.orgName, nil)
	for repo, err := range iter {
		if err != nil {
			log.Error().Err(err).Msg("GitHub list alerts request failed!")
			return err
		}

		project := projects.GetProject(*repo.Name)

		iter := cql.GhClient.CodeScanning.ListAlertsForRepoIter(cql.ctx, cql.orgName, *repo.Name, nil)
		for alert, err := range iter {
			if err != nil {
				log.Error().Err(err).Msg("GitHub list alerts request failed!")
				continue
			}
			if *alert.State == Open {
				fmt.Printf("%s, %s, %s\n", *alert.HTMLURL, *alert.Rule.Description, *alert.Rule.SecuritySeverityLevel)
				if severity, ok := configs.SeverityString[*alert.Rule.SecuritySeverityLevel]; !ok {
					log.Error().Err(err).Msg("Unhandled severity type")
				} else {
					finding := &Finding{
						Description: *alert.Rule.Description,
						Severity:    configs.FindingSeverityType(severity),
					}
					fmt.Println(finding)
					project.Findings = append(project.Findings, finding)
				}
			}
		}
	}
	return nil
}
