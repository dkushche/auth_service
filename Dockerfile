FROM golang:1.18.0-bullseye AS build

WORKDIR /app

COPY . .

RUN go mod download
RUN go build -a -ldflags "-linkmode external -extldflags '-static' -s -w"

FROM scratch

COPY --from=build /app/auth_service /usr/bin/

ENTRYPOINT ["auth_service"]
