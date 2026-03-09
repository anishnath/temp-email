FROM golang:1.22 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o latex-api ./cmd/

FROM ubuntu:22.04
RUN apt-get update && apt-get install -y texlive-base texlive-latex-base texlive-latex-extra && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/latex-api /usr/local/bin/
EXPOSE 8080
CMD ["latex-api"]
