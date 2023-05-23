module github.com/underdog-tech/vulnbot

go 1.20

require (
	github.com/BurntSushi/toml v1.2.1
	github.com/gookit/color v1.5.3
	github.com/joho/godotenv v1.5.1
	github.com/rs/zerolog v1.29.1
	github.com/shurcooL/githubv4 v0.0.0-20230424031643-6cea62ecd5a9
	github.com/slack-go/slack v0.12.2
	github.com/spf13/cobra v1.7.0
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.8.3
	golang.org/x/exp v0.0.0-20230522175609-2e198f4a06a1
	golang.org/x/oauth2 v0.8.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/gorilla/websocket v1.5.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/shurcooL/graphql v0.0.0-20220606043923-3cf50f8a0a29 // indirect
	github.com/stretchr/objx v0.5.0 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	golang.org/x/net v0.10.0 // indirect
	golang.org/x/sys v0.8.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/protobuf v1.30.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// Excluding these because https://pkg.go.dev/vuln/GO-2021-0113
// These are needed by google.golang.org/appengine
// Which is needed by golang.org/x/oauth2
// But everything seems to work without it, so ¯\_(ツ)_/¯
exclude (
	golang.org/x/text v0.3.0
	golang.org/x/text v0.3.2
)
