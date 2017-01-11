vendor: deps
	-rm -fR vendor
	govendor init
	govendor add +external

deps:
	go get -u github.com/kardianos/govendor
	
build:
	@[ -d .build ] || mkdir .build
	CGO_ENABLED=0 go build -ldflags="-s -w" -o .build/nginx-visor cmd/main.go
	file  .build/nginx-visor
	du -h .build/nginx-visor

.PHONY: build