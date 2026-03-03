package querying

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/google/go-github/v84/github"

	"github.com/underdog-tech/vulnbot/configs"
	"github.com/underdog-tech/vulnbot/logger"
)

const Open = "open"

type CodeQLEnvironment struct {
	Language string `json:"language"`
}

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
	log := logger.Get()
	defer wg.Done()

	iter := cql.GhClient.CodeScanning.ListAlertsForOrgIter(
		cql.ctx,
		cql.orgName,
		&github.AlertListOptions{State: Open},
	)

	for alert, err := range iter {
		if err != nil {
			log.Error().Err(err).Msg("GitHub list alerts request failed!")
			return err
		}

		project := projects.GetProject(*alert.Repository.Name)

		codeQLEnv := &CodeQLEnvironment{}
		if err := json.Unmarshal([]byte(*alert.MostRecentInstance.Environment), codeQLEnv); err != nil {
			log.Error().Err(err).Msg("Failed to unmarshall alert environment json")
			continue
		}

		finding := &Finding{
			Description: *alert.Rule.Description,
			Severity: configs.FindingSeverityType(
				configs.SeverityString[*alert.Rule.SecuritySeverityLevel],
			),
			Ecosystem: configs.FindingEcosystemType(codeQLEnv.Language),
		}
		project.Findings = append(project.Findings, finding)
	}
	return nil
}
