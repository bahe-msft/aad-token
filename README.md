## Setup

- Install Go: https://go.dev/doc/install

## Compile and run from local

```
$ ls .
main.go pod.yaml
$ go run main.go 
```

## Run inside a Kubernetes cluster

```
$ kubectl apply -f pod.yaml
$ kubectl get pods
NAME                  READY   STATUS    RESTARTS   AGE
network-capture-pod   2/2     Running   0          50s
$ kubectl logs -f network-capture-pod -c call-aad-login
``` 

When running with pod mode, a sidecar container `network-capture` will be created for running tcpdump in the background.
We can use pod exec to get into the pod and retrieve the tcpdump artifacts.

## Program output

The program attempts to connect to the server via h2. Any non-h2 connections will be closed. If you see output like the following, it means the program has established a h2 connection:

```
CLIENT_HANDSHAKE_TRAFFIC_SECRET <omitted>
SERVER_HANDSHAKE_TRAFFIC_SECRET <omitted>
CLIENT_TRAFFIC_SECRET_0 <omitted>
SERVER_TRAFFIC_SECRET_0 <omitted>
time=2024-02-15T22:03:06.988Z level=INFO source=/app/main.go:221 msg="tls handshake done" protocol=""
time=2024-02-15T22:03:07.048Z level=INFO source=/app/main.go:192 msg="closing non-h2 connection"
CLIENT_HANDSHAKE_TRAFFIC_SECRET <omitted>
SERVER_HANDSHAKE_TRAFFIC_SECRET <omitted>
CLIENT_TRAFFIC_SECRET_0 <omitted>
SERVER_TRAFFIC_SECRET_0 <omitted>
time=2024-02-15T22:03:07.339Z level=INFO source=/app/main.go:221 msg="tls handshake done" protocol=h2
time=2024-02-15T22:03:07.498Z level=INFO source=/app/main.go:202 msg="new connection" key=20.190.190.131:443:172.24.0.34:41952 protocol=h2
time=2024-02-15T22:03:24.365Z level=INFO source=/app/main.go:265 msg="request count" count=100
time=2024-02-15T22:03:41.367Z level=INFO source=/app/main.go:265 msg="request count" count=200
```

The http client has been configured to dump the TLS client keys (using NSS key log format) to the stdout:

```
CLIENT_HANDSHAKE_TRAFFIC_SECRET 0fa0dc2c6798d2f0e257a7f3c945da0293d9aae192cca62a46d208d2d1c18803 10e2e060764a4b6412ef893d32265da8f992caa5906bd18de081a43ff914cfb8e16798ae9fe3506db8847319135a1af8
SERVER_HANDSHAKE_TRAFFIC_SECRET 0fa0dc2c6798d2f0e257a7f3c945da0293d9aae192cca62a46d208d2d1c18803 05c1a6f5b91cc183e261b751e212000e9dcbfc114a29338d559ee13526f34dce2bc115560a4b270f19a528e3379c2cae
CLIENT_TRAFFIC_SECRET_0 0fa0dc2c6798d2f0e257a7f3c945da0293d9aae192cca62a46d208d2d1c18803 cafd284a857db9a2bba46f2129b126e00a8e85bd46fa8a8cab9c6a92bcd2087340e99b07574fe32e26e5bfd5221a3fbc
SERVER_TRAFFIC_SECRET_0 0fa0dc2c6798d2f0e257a7f3c945da0293d9aae192cca62a46d208d2d1c18803 04d3f1950cc85385271fc17148ad4d4ba42bc6a638ec658205a0b1cb48a214d003d00021f5931babf6b0ea1c3ecd2092
time=2024-02-15T22:03:07.339Z level=INFO source=/app/main.go:221 msg="tls handshake done" protocol=h2
time=2024-02-15T22:03:07.498Z level=INFO source=/app/main.go:202 msg="new connection" key=20.190.190.131:443:172.24.0.34:41952 protocol=h2
```

The lines starts with `CLIENT_HANDSHAKE_XXX` / `SERVER_HANDSHAKE_XXX` / `CLIENT_TRAFFIC_XXX` / `CLIENT_TRAFFIC_XXX` are the exchanged keys used in the TLS connection.
They can be saved to NSS log file and used to decrypt the tcpdump later.