GO ?= go

.PHONY: all web build run test clean
all: build

web:
	cd web && npm install && npm run build

build: web
	$(GO) build -o bin/httpmonitor .

run: build
	./bin/httpmonitor -capture -open

test:
	$(GO) test ./...

clean:
	rm -rf bin web/dist/assets web/dist/index.html
