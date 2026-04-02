all: build test
	CGO_ENABLED=0 go build -o netforge
build:
	CGO_ENABLED=0 go build -o netforge
test:
	sudo go test -cover
run: build
	sudo ./netforge
