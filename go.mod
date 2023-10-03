module github.com/underdog-tech/vulnbot

go 1.20

require (
	github.com/deckarep/golang-set/v2 v2.3.0
	github.com/gookit/color v1.5.3
	github.com/rs/zerolog v1.29.1
	github.com/shurcooL/githubv4 v0.0.0-20230424031643-6cea62ecd5a9
	github.com/slack-go/slack v0.12.2
	github.com/spf13/cobra v1.7.0
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.16.0
	github.com/stretchr/testify v1.8.3
	golang.org/x/exp v0.0.0-20230522175609-2e198f4a06a1
	golang.org/x/oauth2 v0.8.0
	golang.org/x/text v0.9.0
)

require (
	github.com/aws/aws-sdk-go-v2 v1.21.0 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.1.41 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.4.35 // indirect
	github.com/aws/aws-sdk-go-v2/service/ecr v1.20.0 // indirect
	github.com/aws/smithy-go v1.14.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/gorilla/websocket v1.5.0 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/pelletier/go-toml/v2 v2.0.8 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/shurcooL/graphql v0.0.0-20220606043923-3cf50f8a0a29 // indirect
	github.com/spf13/afero v1.9.5 // indirect
	github.com/spf13/cast v1.5.1 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/stretchr/objx v0.5.0 // indirect
	github.com/subosito/gotenv v1.4.2 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	golang.org/x/net v0.10.0 // indirect
	golang.org/x/sys v0.8.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/protobuf v1.30.0 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// Excluding these because https://pkg.go.dev/vuln/GO-2021-0113
// These are needed by google.golang.org/appengine
// Which is needed by golang.org/x/oauth2
// But everything seems to work without it, so ¯\_(ツ)_/¯
exclude (
	golang.org/x/text v0.3.0
	golang.org/x/text v0.3.2
	golang.org/x/text v0.3.3
	golang.org/x/text v0.3.4
	golang.org/x/text v0.3.6
	golang.org/x/text v0.3.7
	google.golang.org/grpc v1.19.0
	google.golang.org/grpc v1.20.1
	google.golang.org/grpc v1.21.1
	google.golang.org/grpc v1.23.0
	google.golang.org/grpc v1.25.1
	google.golang.org/grpc v1.26.0
	google.golang.org/grpc v1.27.0
	google.golang.org/grpc v1.27.1
	google.golang.org/grpc v1.28.0
	google.golang.org/grpc v1.29.1
	google.golang.org/grpc v1.30.0
	google.golang.org/grpc v1.31.0
	google.golang.org/grpc v1.31.1
	google.golang.org/grpc v1.33.2
	google.golang.org/grpc v1.34.0
	google.golang.org/grpc v1.35.0
	gopkg.in/yaml.v2 v2.2.2
)
