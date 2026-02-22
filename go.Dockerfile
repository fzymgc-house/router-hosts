# syntax=docker/dockerfile:1

# ---------- builder ----------
FROM golang:1.25-alpine AS builder

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
FROM gcr.io/distroless/static:nonroot

COPY --from=builder /out/router-hosts /usr/local/bin/router-hosts
COPY --from=builder /out/operator /usr/local/bin/operator

EXPOSE 50051

ENTRYPOINT ["router-hosts"]
CMD ["serve", "--config", "/etc/router-hosts/server.toml"]
