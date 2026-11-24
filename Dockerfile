FROM golang:alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /t3-gate .

FROM scratch
COPY --from=build /t3-gate /t3-gate
ENTRYPOINT ["/t3-gate"]
