all: test
	go build -o netforge
test:
	go test -cover
