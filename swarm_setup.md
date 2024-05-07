Initialise the swarm. Since this is a Windows machine we can't do anything fancy like add workers
```
docker swarm init
```

Create default registry
```
docker service create --name registry --publish published=5000,target=5000 registry:2
```

Create a test network
```
docker network create --driver=overlay udptunnel-test
```

Build the containers and add them to the registry, e.g.
```
docker compose build
docker compose push
```

Deploy the stack
```
 docker stack deploy --compose-file .\docker-compose.swarm.yml stackdemo
 ```