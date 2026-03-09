.PHONY: build run test docker clean

build:
	go build -o bin/latex-api ./cmd/

run:
	go run ./cmd/

test:
	go test ./...

docker:
	docker build -t latex-api .

clean:
	rm -rf bin/
