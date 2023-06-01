FROM rust:slim-buster as builder
RUN mkdir -p /src
WORKDIR /src
COPY . .
RUN cargo build --release

FROM debian:buster-slim
COPY --from=builder /src/target/release/ghctl /usr/local/bin/ghctl
ENTRYPOINT ["/usr/local/bin/ghctl"]
