## IPSec Session Hijacking

### *Overview*

This project explores the protocol IPsec (Internet Protocol Security) and demonstrates how IPsec sessions can be hijacked. The project involves setting up an environment using Docker containers, understanding IPsec protocols, and developing an attacker program to hijack IPsec/TCP sessions.

### *Goals*

* Understand the process of hijacking IPsec sessions.
* Learn the following key concepts:
  * Sniffing IPv4/ESP/TCP packets.
  * Dumping keys to generate HMAC signatures.
  * Fabricating IPv4/ESP/TCP packet

### *What is IPsec?*

IPsec is a suite of protocols designed to secure Internet Protocol (IP) communications through authenticating and encrypting each IP packet in a communication session. The two main protocols used in IPsec are:

* Internet Key Exchange (IKE): Used for negotiation and establishment of security associations (SAs).
* Encapsulating Security Payload (ESP): Provides confidentiality, integrity, and authentication.

### *Key Concepts*

1. **Security Associations (SAs):**
   * Govern unidirectional traffic security.
   * Identified by Security Parameter Index (SPI), IP destination address, and protocol identifier (ESP).
2. **Encapsulating Security Payload (ESP):**
   * Protects data integrity and confidentiality.
   * Operates in two modes:
     * Transport Mode: Protects payload, preserves original IP header.
     * Tunnel Mode: Protects entire IP packet, adds new IP header.

### *Case Study: VoWi-Fi with IPsec Protection*

#### IPSec protection over VoWi-Fi traffic traversing public domain

![img](https://imgur.com/ir83SQj.jpg)

#### Attacker can manipulate IMS call service operation (IMS vulnerabilities can be exposed)

![img](https://imgur.com/DtyQFvp.jpg)

### *Attacker Program Tasks*

* Monitor and collect session information from ESP and TCP headers.
* Retrieve IPsec SA from the Security Association Database (SADB) and dump the key.
* Fabricate IPv4/ESP/TCP packets with correct fields and checksums.
* Generate ESP padding and authentication data.

### *Environment Setup*

#### Build the project image

You need to install the docker at first,

and build the project image with

```bash
sudo docker build -t ipsec-hijacking -f ipsec-hijacking.Dockerfile .
```

#### Run the project containers

Run the server and client with

```bash
sudo docker compose -f ipsec-hijacking-docker-compose.yml up -d
```

### *Usage*

#### Run the server

In the server container,

run the server with

```bash
docker exec -it server bash
./server 1111
```

#### Run the client

In the client container,

run the client with

```bash
docker exec -it client bash
./client 172.18.100.254 1111 2222
```

#### Run the hijacking tool

In the client container,

create the hijacking tool,

and run the hijacking tool with

```bash
docker exec -it client bash
make
./hijack eth0
```

#### Stop and remove the containers

Remove the docker network 

and the client/server containers with

```bash
sudo docker compose -f ipsec-hijacking-docker-compose.yml down
```

#### Remove the image

Remove the docker image with

```bash
docker rmi ipsec-hijacking
```

#### Restart the container

If the container exited after rebooting,
restart the container with

```bash
docker restart $container_name
```

### *Verification Steps*
































































* **The server can receive fabricated IPsec packets belonging to the existing IPsec session**
  ![img](https://imgur.com/yidH1yh.jpg)






































* **The attacker program can correctly exchange TCP packets with the server through the fabricated IPsec packets**
  ![img](https://imgur.com/4ol8a0C.jpg)
* **Multiple Handshake Tests with Three Flags**
  ![img](https://imgur.com/RH485G2.jpg)

### *Environment*

#### IP address

In the default setting of the docker-compose,

- ip of server is 172.18.100.254:1111
- ip of client is 172.18.1.1:2222
- external port to access SSH in the server is 3333
- external port to access SSH in the client is 4444

#### Configuration

The script "src/scripts/config.sh" will depend on the setting of the docker-compose
