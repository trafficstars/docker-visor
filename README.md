Docker-visor
============

This is observing service which listens to docker events and automatically register/deregister services in Consul.

Run docker visor
----------------

```sh
docker run -id \
    --name docker-visor \
    --memory 100MB \
    --restart always \
    -p :8000 \
    -e HOST_IP=${HOST_IP} \
    -e REGISTRY_DSN="http://${HOST}?dc=dc1&refresh_interval=5" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    docker-visor
```

User service example
--------------------

```dockerfile
FROM ubuntu

ENV SERVICE_NAME=myawesomeservice
# Optional custom public port
ENV SERVICE_PORT=8081
# Optional tags
ENV TAG_NAME1=100
ENV TAG_NAME2=200

# Health check optional
ENV CHECK_INTERVAL=5s
ENV CHECK_TIMEOUT=1s
ENV CHECK_TTL=10m
# {address} will be replaced automaticaly on host IP:{SERVICE_PORT}
ENV CHECK_HTTP=http://{address}/health-check

ENV CHECK_DEREGISTER_AFTER=10m
```
