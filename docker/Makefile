build:
	@[ -d .build ] || mkdir .build
	CGO_ENABLED=0 go build -ldflags="-s -w" -o .build/docker-visor ../cmd/main.go
	file  .build/docker-visor
	du -h .build/docker-visor
	
image: build
	docker build -t docker-visor .

.PHONY: build