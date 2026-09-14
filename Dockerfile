FROM rust:latest AS build

COPY . /src
WORKDIR /src
RUN cargo build --release

FROM debian:trixie AS environment

RUN apt-get update && apt-get install -y \
      libssl3 ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /src/target/release/rsdhcp /usr/bin/rsdhcp
CMD ["-c", "/rsdhcp.yaml"]
ENTRYPOINT ["rsdhcp"]
