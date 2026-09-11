FROM rust:latest AS build

COPY . /src
WORKDIR /src/rsdhcp
RUN cargo build --release

FROM debian:bookworm AS environment

RUN apt-get update && apt-get install -y \
      libssl3 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build /src/rsdhcp/target/release/rsdhcp /usr/bin/rsdhcp
CMD ["-c", "/rsdhcp.yaml"]
ENTRYPOINT ["rsdhcp"]
