
PROJECT_NAME := sbomqs
BUILD_FILE := ./build/sbomqs

.PHONY: all
all: dep test build 

.PHONY: dep
dep:
	go mod vendor 
	go mod tidy 

.PHONY: test 
test:
	go test -cover -race ./...

.PHONY: build
build:
	go build -a -installsuffix cgo -o $(BUILD_FILE) main.go 

.PHONY: clean
clean:
	rm -f $(BUILD_FILE)