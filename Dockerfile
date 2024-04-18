FROM rust:1.77.2-alpine as builder
RUN apk update && apk add --no-cache \
   musl-dev git \
   openssl openssl-dev openssl-libs-static \
   build-base

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY ./tuic ./tuic
COPY ./tuic-quinn ./tuic-quinn
COPY ./tuic-client ./tuic-client
COPY ./tuic-server ./tuic-server
ENV USTFLAGS="-C target-feature=+crt-static"
RUN cargo build --release

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/target/release/tuic-client ./
COPY --from=builder /app/target/release/tuic-server ./
CMD ["/app/tuic-server"]

