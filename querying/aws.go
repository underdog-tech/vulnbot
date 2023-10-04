package querying

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"sync"

	"github.com/underdog-tech/vulnbot/config"
	"github.com/underdog-tech/vulnbot/logger"

	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrTypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

type ecrClient interface {
	DescribeImageScanFindings(context.Context, *ecr.DescribeImageScanFindingsInput, ...func(*ecr.Options)) (*ecr.DescribeImageScanFindingsOutput, error)
	DescribeRepositories(context.Context, *ecr.DescribeRepositoriesInput, ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error)
	DescribeImages(context.Context, *ecr.DescribeImagesInput, ...func(*ecr.Options)) (*ecr.DescribeImagesOutput, error)
}

type AwsDataSource struct {
	EcrClient ecrClient
	conf      config.Config
	ctx       context.Context
}

var ecrSeverities = map[string]config.FindingSeverityType{
	"INFORMATIONAL": config.FindingSeverityInfo,
	"LOW":           config.FindingSeverityLow,
	"MEDIUM":        config.FindingSeverityModerate,
	"HIGH":          config.FindingSeverityHigh,
	"CRITICAL":      config.FindingSeverityCritical,
	"UNDEFINED":     config.FindingSeverityUndefined,
}

func NewAWSClient(conf config.Config, env config.Env) AwsDataSource {
	log := logger.Get()

	cfg, err := awsConfig.LoadDefaultConfig(context.TODO(), awsConfig.WithRegion(env.AwsRegion))
	if err != nil {
		log.Error().Err(err).Msg("...")
	}

	return AwsDataSource{
		EcrClient: ecr.NewFromConfig(cfg),
		conf:      conf,
		ctx:       context.Background(),
	}
}

// CollectFindings retrieves findings for repositories and processes them.
// It collects repositories from AWS ECR, filters them based on a provided filter function,
// and processes the findings for each repository.
//
// Parameters:
//
//	adc: An AwsDataSource instance for accessing AWS resources.
//	projects: A ProjectCollection containing information about projects.
//	wg: A WaitGroup for managing goroutine synchronization.
//
// Returns:
//
//	An error if there was a problem during the process; otherwise, nil.
func (adc *AwsDataSource) CollectFindings(projects *ProjectCollection, wg *sync.WaitGroup) error {
	log := logger.Get()
	defer wg.Done()

	describeRepositoriesParams := &ecr.DescribeRepositoriesInput{}
	var allRepositories []*ecrTypes.Repository

	for {
		ecrRepositories, err := adc.EcrClient.DescribeRepositories(adc.ctx, describeRepositoriesParams)
		if err != nil {
			log.Error().Err(err).Msg("Describe repositories query failed!")
			return err
		}

		// Create a temporary slice to store the repositories from this page
		tempRepositories := make([]*ecrTypes.Repository, len(ecrRepositories.Repositories))
		for i, repo := range ecrRepositories.Repositories {
			tempRepositories[i] = &repo
		}

		// Append the current page of results to the overall list
		allRepositories = append(allRepositories, tempRepositories...)

		if ecrRepositories.NextToken == nil {
			// No more results, break the loop
			break
		}

		// Set the next token to retrieve the next page of results
		describeRepositoriesParams.NextToken = ecrRepositories.NextToken
	}

	for _, repo := range allRepositories {
		err := adc.processImageScanFindings(projects, *repo)
		if err != nil {
			log.Warn().Err(err).Str("repository", *repo.RepositoryName).Msg("Error processing repository findings.")
		}
	}

	return nil
}

// processImageScanFindings retrieves and processes image scan findings for a specific image in a repository.
// It handles pagination by utilizing the NextToken to fetch all results.
// It updates or adds the findings to the project based on the retrieved information.
func (adc *AwsDataSource) processImageScanFindings(projects *ProjectCollection, repo ecrTypes.Repository) error {
	log := logger.Get()

	project := projects.GetProject(*repo.RepositoryName)
	project.Links["ECR"] = *repo.RepositoryUri

	latestImage, err := adc.getLatestImage(*repo.RepositoryName)
	if err != nil {
		return err
	}

	var nextToken *string

	for {
		describeImageScanFindingsParams := &ecr.DescribeImageScanFindingsInput{
			RepositoryName: repo.RepositoryName,
			ImageId: &ecrTypes.ImageIdentifier{
				ImageDigest: latestImage.ImageDigest,
				ImageTag:    &latestImage.ImageTags[len(latestImage.ImageTags)-1],
			},
			NextToken: nextToken,
		}
		repoVulnerabilities, err := adc.EcrClient.DescribeImageScanFindings(adc.ctx, describeImageScanFindingsParams)
		if err != nil {
			return err
		}

		for _, vuln := range repoVulnerabilities.ImageScanFindings.Findings {
			identifiers := FindingIdentifierMap{}

			findingType := extractFindingType(*vuln.Name)
			if findingType == "" {
				log.Debug().Msg("No finding type found.")
				break
			}

			identifiers[FindingIdentifierType(findingType)] = findingType
			finding := project.GetFinding(identifiers)

			finding.Description = *vuln.Description

			packageName := extractPackageName(vuln.Attributes)
			if packageName != "" {
				finding.PackageName = packageName
			}

			finding.Severity = ecrSeverities[string(vuln.Severity)]
		}

		// If there are no more results, update the nextToken and continue the loop
		if repoVulnerabilities.NextToken != nil {
			nextToken = repoVulnerabilities.NextToken
		} else {
			break // No more results to fetch, exit the loop.
		}
	}

	return nil
}

func (adc *AwsDataSource) getLatestImage(repositoryName string) (*ecrTypes.ImageDetail, error) {
	describeImagesParams := &ecr.DescribeImagesInput{
		RepositoryName: &repositoryName,
	}

	// Get a list of images in the repository
	repoImages, err := adc.EcrClient.DescribeImages(adc.ctx, describeImagesParams)
	if err != nil {
		return nil, err
	}

	// Sort images by creation date (latest first)
	sort.SliceStable(repoImages.ImageDetails, func(i, j int) bool {
		return repoImages.ImageDetails[i].ImagePushedAt.After(*repoImages.ImageDetails[j].ImagePushedAt)
	})

	// Return the latest image
	if len(repoImages.ImageDetails) > 0 {
		return &repoImages.ImageDetails[0], nil
	}

	return nil, fmt.Errorf("no images found in the repository")
}

func extractFindingType(vulnerabilityName string) string {
	regex := regexp.MustCompile(`^([A-Za-z]+)-\d+-\d+$`)

	matches := regex.FindStringSubmatch(vulnerabilityName)
	if len(matches) >= 2 {
		return matches[1]
	}
	return ""
}

func extractPackageName(attributes []ecrTypes.Attribute) string {
	for _, attr := range attributes {
		if attr.Key != nil && *attr.Key == "package_name" {
			return *attr.Value
		}
	}
	return ""
}
