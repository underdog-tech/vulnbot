package querying

import (
	"context"
	"sync"

	"github.com/underdog-tech/vulnbot/config"

	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/underdog-tech/vulnbot/logger"
)

type ecrClient interface {
	DescribeImageScanFindings(context.Context, *ecr.DescribeImageScanFindingsInput, ...func(*ecr.Options)) (*ecr.DescribeImageScanFindingsOutput, error)
}

type AwsDataSource struct {
	EcrClient ecrClient
	conf      config.Config
	ctx       context.Context
}

func NewAWSClient(conf config.Config, env config.Env) AwsDataSource {
	log := logger.Get()

	cfg, err := awsConfig.LoadDefaultConfig(context.TODO(), awsConfig.WithRegion(env.AwsRegion))
	if err != nil {
		log.Error().Err(err).Msg("GitHub repository query failed!")
	}

	return AwsDataSource{
		EcrClient: ecr.NewFromConfig(cfg),
		conf:      conf,
		ctx:       context.Background(),
	}
}

func (adc *AwsDataSource) CollectFindings(projects *ProjectCollection, wg *sync.WaitGroup) error {
	defer wg.Done()
	return nil
}
