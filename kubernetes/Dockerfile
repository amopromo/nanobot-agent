# nanobot-k8s-monitoring
#   docker build -t <usuario>/nanobot-k8s-agent:0.5.0 kubernetes/
#   docker push <usuario>/nanobot-k8s-agent:0.5.0
# Binário Go estático (sem CGO): a imagem final só tem ele e os certificados (distroless).
FROM golang:1.26-trixie AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/nanobot-k8s-monitoring . && \
    mkdir -p /out/data

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /out/nanobot-k8s-monitoring /usr/local/bin/nanobot-k8s-monitoring
COPY --from=build --chown=10001:10001 /out/data /data
USER 10001:10001
ENV BUFFER_DIR=/data HOME=/data
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/nanobot-k8s-monitoring"]
