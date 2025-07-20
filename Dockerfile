# Stage 1: builder
FROM rust:latest AS builder
WORKDIR /app
COPY . .
# Install musl and upx for static linking and compression
RUN apt-get update && apt-get install -y musl-tools upx && \
    rustup target add x86_64-unknown-linux-musl && \
    cargo build --release --target x86_64-unknown-linux-musl && \
    strip target/x86_64-unknown-linux-musl/release/selenia_server && \
    upx --lzma --best target/x86_64-unknown-linux-musl/release/selenia_server

# Stage 2: minimal image
FROM scratch
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/selenia_server /sws
EXPOSE 80 443
ENTRYPOINT ["/sws"] 