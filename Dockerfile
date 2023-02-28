FROM alpine:3.17 AS base

WORKDIR /app

FROM base AS builder

COPY . .

RUN apk update && apk upgrade && apk add go
RUN go build .

FROM base AS final

COPY --from=builder /app/dependabot-alert-bot /app/

ENTRYPOINT [ "./dependabot-alert-bot" ]
