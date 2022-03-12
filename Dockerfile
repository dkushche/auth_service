FROM golang:1.17-bullseye AS build

WORKDIR /app

COPY . .

RUN go mod download
RUN go build -a -ldflags "-linkmode external -extldflags '-static' -s -w"

FROM scratch

COPY --from=build /app/roothazardlab_backend /usr/bin/

ENTRYPOINT ["roothazardlab_backend"]
