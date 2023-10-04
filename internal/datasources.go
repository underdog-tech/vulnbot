package internal

import (
	"sync"

	"github.com/underdog-tech/vulnbot/config"
	"github.com/underdog-tech/vulnbot/logger"
	"github.com/underdog-tech/vulnbot/querying"
)

func GetDataSources(env config.Env, cfg config.Config) []querying.DataSource {
	dataSources := []querying.DataSource{}

	if env.GithubToken != "" {
		ghds := querying.NewGithubDataSource(cfg, env)
		dataSources = append(dataSources, &ghds)
	}

	if env.AwsRegion != "" {
		adc := querying.NewAWSClient(cfg, env)
		dataSources = append(dataSources, &adc)
	}

	return dataSources
}

func QueryAllDataSources(dataSources *[]querying.DataSource) *querying.ProjectCollection {
	log := logger.Get()
	projects := querying.NewProjectCollection()
	wg := new(sync.WaitGroup)

	for _, ds := range *dataSources {
		wg.Add(1)
		// go func(currentDS querying.DataSource) {
		err := ds.CollectFindings(projects, wg)
		if err != nil {
			log.Error().Err(err).Type("datasource", ds).Msg("Failed to query datasource")
		}
		// }(ds)
	}
	wg.Wait()

	return projects
}
