# Basic dockerns example

This is a basic example to help you to quickly deploy a very simple dockerns setup, with default config.


## Quickstart

Just run docker-compose up:
```
docker-compose up
```

## Discover

To test automatic container DNS:
```
$ dig @127.0.0.1 -p 5370 +short simple-app-1.docker
172.90.137.2
172.90.136.3
```

This returns all IPs of the container. To get a specific network IP, just pass the network name as subdomain:
```
$ dig @127.0.0.1 -p 5370 +short simple_default.simple-app-1.docker
172.90.136.3
$ dig @127.0.0.1 -p 5370 +short simple_net1.simple-app-1.docker
172.90.137.2
```

Notes about names:

* As we use docker-compose, all elements are prefixed with `simple`, as it is the name of our stack. Use the `--project-name <name>` to change this behavior.
* Same for networks, you can use `docker network ls` to get the name of the network. Also, to change names, you must define them explicitely into your `docker-compose.yml` file.


When used with docker-compose, a container will be available with the following records:

* `<container_name>.<domain>`
* `<network_name>.<container_name>.<domain>`
* `<port_name>.<container_name>.<domain>`
* `<container_name>.<project>.<domain>`
* `<network_name>.<container_name>.<project><domain>`
* `<port_name>.<network_name>.<container_name>.<project><domain>`

This behavior can be changed via the configuration file.

When used with docker compose, we can get all IPs of all interfaces:
```
$ dig @127.0.0.1 -p 5370 +short app.simple.docker
172.90.147.2
172.90.147.3
172.90.147.4
172.90.146.4
172.90.146.3
172.90.146.5
```

But we will probably want to limit to a specific network:
```
$ dig @127.0.0.1 -p 5370 +short simple_net1.app.simple.docker
172.90.147.4
172.90.147.3
172.90.147.2
```

Finally to fetch individual instances:
```
$ dig @127.0.0.1 -p 5370 +short simple_net1.1.app.simple.docker
172.90.147.3
$ dig @127.0.0.1 -p 5370 +short simple_net1.2.app.simple.docker
172.90.147.4
$ dig @127.0.0.1 -p 5370 +short simple_net1.3.app.simple.docker
172.90.147.2
```

To test custom DNS label record:
```
$ dig @127.0.0.1 -p 5370 +short  myapp.docker
172.90.150.3
172.90.150.5
172.90.150.4

$ dig @127.0.0.1 -p 5370 +short app-public.example.org
1.2.3.4
```

