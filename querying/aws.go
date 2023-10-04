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
	var allRepositories []ecrTypes.Repository

	for {
		ecrRepositories, err := adc.EcrClient.DescribeRepositories(adc.ctx, describeRepositoriesParams)
		if err != nil {
			log.Error().Err(err).Msg("Describe repositories query failed!")
			return err
		}

		allRepositories = append(allRepositories, ecrRepositories.Repositories...)

		if ecrRepositories.NextToken == nil {
			break
		}

		// Set the next token to retrieve the next page of results
		describeRepositoriesParams.NextToken = ecrRepositories.NextToken
	}

	for _, repo := range allRepositories {
		err := adc.processImageScanFindings(projects, repo)
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
	var imageVulnerabilities []ecrTypes.ImageScanFinding

	for {
		lastImageTag, err := extractLastImageTag(latestImage.ImageTags)
		if err != nil {
			return err
		}

		describeImageScanFindingsParams := &ecr.DescribeImageScanFindingsInput{
			RepositoryName: repo.RepositoryName,
			ImageId: &ecrTypes.ImageIdentifier{
				ImageDigest: latestImage.ImageDigest,
				ImageTag:    &lastImageTag,
			},
			NextToken: nextToken,
		}
		repoVulnerabilities, err := adc.EcrClient.DescribeImageScanFindings(adc.ctx, describeImageScanFindingsParams)
		if err != nil {
			return err
		}

		if repoVulnerabilities.ImageScanFindings != nil {
			imageVulnerabilities = append(imageVulnerabilities, *&repoVulnerabilities.ImageScanFindings.Findings...)
		}

		if repoVulnerabilities.NextToken != nil {
			nextToken = repoVulnerabilities.NextToken
		} else {
			break
		}
	}

	for _, vuln := range imageVulnerabilities {
		identifiers := FindingIdentifierMap{}

		findingType := extractFindingType(*vuln.Name)
		if findingType == "" {
			log.Debug().Msg("No finding type found.")
			break
		}

		identifiers[FindingIdentifierType(findingType)] = findingType
		log.Debug().Any("identifiers", identifiers).Msg("Processing finding.")

		finding := project.GetFinding(identifiers)

		if vuln.Description != nil {
			finding.Description = *vuln.Description
		}

		packageName := extractPackageName(vuln.Attributes)
		if packageName != "" {
			finding.PackageName = packageName
		}

		finding.Severity = ecrSeverities[string(vuln.Severity)]
	}

	return nil
}

// Get a list of images in the repository
func (adc *AwsDataSource) getLatestImage(repositoryName string) (*ecrTypes.ImageDetail, error) {
	var nextToken *string
	var images []ecrTypes.ImageDetail

	for {
		describeImagesParams := &ecr.DescribeImagesInput{
			RepositoryName: &repositoryName,
			NextToken:      nextToken,
		}

		repoImages, err := adc.EcrClient.DescribeImages(adc.ctx, describeImagesParams)
		if err != nil {
			return nil, err
		}

		images = append(images, repoImages.ImageDetails...)

		if repoImages.NextToken != nil {
			nextToken = repoImages.NextToken
		} else {
			break
		}

	}

	// Sort images by creation date (latest first)
	sort.SliceStable(images, func(i, j int) bool {
		return images[i].ImagePushedAt.After(*images[j].ImagePushedAt)
	})

	// Return the latest image
	if len(images) > 0 {
		return &images[0], nil
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

func extractLastImageTag(imageTags []string) (string, error) {
	lastImageTagIndex := len(imageTags) - 1
	if lastImageTagIndex >= 0 {
		lastImageTag := imageTags[lastImageTagIndex]
		return lastImageTag, nil
	}

	return "", fmt.Errorf("No image tag found.")
}
