FROM golang:1.20 AS build

WORKDIR /app

# Make sure the dependency downloading can be cached
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o ./vulnbot

FROM build as test
RUN go test -v -race ./...

# Final image uses a barebones image
FROM gcr.io/distroless/base-debian11 AS release

WORKDIR /
COPY --from=build /app/vulnbot /vulnbot

USER nonroot:nonroot

ENTRYPOINT [ "/vulnbot" ]
