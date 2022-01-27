LDFLAGS=-ldflags "-s -w -X main.Version=$(shell git describe --abbrev=0 --always --tags)"

build:
	#Linux
	GOOS=linux GOARCH=amd64 go build -o bin/genconfig ${LDFLAGS} ./cmd/genconfig/main.go

	#Windows
	GOOS=windows GOARCH=amd64 go build -o bin/genconfig.exe ${LDFLAGS} ./cmd/genconfig/main.go

clean:
	rm -f bin/*