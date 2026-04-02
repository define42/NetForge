all: build test
	go build -o netforge
build:
	go build -o netforge
test:
	sudo go test -cover
run: build
	sudo ./netforge

