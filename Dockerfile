# syntax=docker/dockerfile:1@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89

# ---------- builder ----------
FROM golang:1.26-alpine@sha256:f23e8b227fb4493eabe03bede4d5a32d04092da71962f1fb79b5f7d1e6c2a17f AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w" \
    -o /out/router-hosts ./cmd/router-hosts

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w" \
    -o /out/operator ./cmd/operator

# ---------- runtime ----------
FROM gcr.io/distroless/static:nonroot@sha256:963fa6c544fe5ce420f1f54fb88b6fb01479f054c8056d0f74cc2c6000df5240

COPY --from=builder /out/router-hosts /usr/local/bin/router-hosts
COPY --from=builder /out/operator /usr/local/bin/operator

EXPOSE 50051

ENTRYPOINT ["router-hosts"]
CMD ["serve", "--config", "/etc/router-hosts/server.toml"]
