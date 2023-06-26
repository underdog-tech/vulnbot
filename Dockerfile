# We want to build on a canonical Golang image to easily use the latest/greatest
FROM golang:1.20 AS build

WORKDIR /app

# Set up pieces necessary for our final release image
RUN echo "nonroot:x:65534:65534:Nonroot:/:" > /etc/passwd.min

# Make sure the dependency downloading can be cached
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o ./vulnbot

# This stage is by default un-used, but allows us to easily run our tests inside
# of an actual Docker image.
FROM build as test
RUN go test -v -race ./...

# Final image uses a barebones image
FROM scratch AS release

WORKDIR /
COPY --from=build /etc/passwd.min /etc/passwd
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

USER nonroot

COPY --from=build /app/vulnbot /vulnbot

ENTRYPOINT [ "/vulnbot" ]
