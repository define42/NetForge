all: test
	go build -o netforge
test:
	sudo go test -cover
