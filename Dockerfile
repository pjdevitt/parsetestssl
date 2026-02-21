# syntax=docker/dockerfile:1

FROM golang:1.24-alpine AS builder
WORKDIR /src

COPY go.mod ./
RUN go mod download

COPY main.go ./
COPY templates ./templates
COPY static ./static

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /app/parsetestssl .

FROM alpine:3.21
WORKDIR /app

RUN addgroup -S app && adduser -S -G app app

COPY --from=builder /app/parsetestssl ./parsetestssl
COPY --from=builder /src/templates ./templates
COPY --from=builder /src/static ./static

USER app
EXPOSE 8080
ENV PORT=8080

ENTRYPOINT ["./parsetestssl"]
