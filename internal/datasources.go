package internal

import (
	"sync"

	"github.com/underdog-tech/vulnbot/configs"
	"github.com/underdog-tech/vulnbot/logger"
	"github.com/underdog-tech/vulnbot/querying"
)

// GetDataSources returns the configured DataSources to query, plus a typed
// reference to the GitHub one specifically (nil if no Github_token is
// configured). The typed reference exists so callers can reach
// GithubDataSource-specific data - namely ForkProjects - that isn't part
// of the generic querying.DataSource interface. It would otherwise be
// erased the moment it's placed in the []querying.DataSource slice below.
func GetDataSources(cfg *configs.Config) ([]querying.DataSource, *querying.GithubDataSource) {
	dataSources := []querying.DataSource{}
	var githubDataSource *querying.GithubDataSource

	if cfg.Github_token != "" {
		ghds := querying.NewGithubDataSource(cfg)
		dataSources = append(dataSources, &ghds)
		githubDataSource = &ghds

		cqlds := querying.NewCodeQLDataSource(cfg)
		dataSources = append(dataSources, &cqlds)
	}

	return dataSources, githubDataSource
}

func QueryAllDataSources(dataSources *[]querying.DataSource) *querying.ProjectCollection {
	log := logger.Get()
	projects := querying.NewProjectCollection()
	wg := new(sync.WaitGroup)

	for _, ds := range *dataSources {
		wg.Add(1)
		go func(currentDS querying.DataSource) {
			err := currentDS.CollectFindings(projects, wg)
			if err != nil {
				log.Error().Err(err).Type("datasource", currentDS).Msg("Failed to query datasource")
			}
		}(ds)
	}
	wg.Wait()

	return projects
}