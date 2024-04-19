FROM rust:1.77-alpine as builder
RUN apk update && apk add --no-cache git \
   musl-dev build-base clang lld compiler-rt \
   openssl openssl-dev openssl-libs-static

ENV CC=clang
ENV RUSTFLAGS="-C linker=clang -C link-arg=-static"

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY ./tuic ./tuic
COPY ./tuic-quinn ./tuic-quinn
COPY ./tuic-client ./tuic-client
COPY ./tuic-server ./tuic-server
RUN cargo build --release

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/target/release/tuic-client ./
COPY --from=builder /app/target/release/tuic-server ./
CMD ["/app/tuic-server"]

