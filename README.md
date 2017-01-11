```
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