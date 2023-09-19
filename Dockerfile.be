FROM golang@sha256:9f2dd04486e84eec72d945b077d568976981d9afed8b4e2aeb08f7ab739292b3 as bootstrap-base
WORKDIR /go/src/app
COPY bootstrap_be/main.go /go/src/app
COPY bootstrap_be/go.mod /go/src/app
COPY bootstrap_be/go.sum /go/src/app
RUN go mod tidy
RUN go mod download
RUN GOOS=linux GOARCH=amd64 go build -o /go/bin/bootstrap

FROM docker.io/envoyproxy/envoy@sha256:5d17b613824732465c64a44ecc4ece631a0054db3ff5f5e3aeedfd095173ab05 as envoy-base
FROM docker.io/hashicorp/consul@sha256:580b5e3b4afc3cd3b638fce7bd2c26bea7491bee12836db41be909b587921720 as consul-base

FROM golang@sha256:9f2dd04486e84eec72d945b077d568976981d9afed8b4e2aeb08f7ab739292b3 as app-base
WORKDIR /go/src/app
COPY be/main.go /go/src/app
COPY be/go.mod /go/src/
COPY be/go.sum /go/src/
RUN go mod tidy
RUN go mod download
RUN GOOS=linux GOARCH=amd64 go build -o /go/bin/server

FROM gcr.io/distroless/base@sha256:e711a716d8b7fe9c4f7bbf1477e8e6b451619fcae0bc94fdf6109d490bf6cea0

LABEL "tee.launch_policy.allow_cmd_override"="false"
LABEL "tee.launch_policy.log_redirect"="always"

COPY envoy/be_proxy.yaml /envoy/be_proxy.yaml

COPY --from=bootstrap-base /go/bin/bootstrap /bootstrap
COPY --from=envoy-base /usr/local/bin/envoy /usr/local/bin/envoy
COPY --from=consul-base /bin/consul /usr/local/bin/consul
COPY --from=app-base /go/bin/server /server

EXPOSE 8082
EXPOSE 8301
EXPOSE 8500
EXPOSE 8301/udp
EXPOSE 8500/udp

WORKDIR /
ENTRYPOINT ["/bootstrap"]