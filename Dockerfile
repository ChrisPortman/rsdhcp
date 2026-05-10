FROM rust:latest AS build

ARG HTTP_PROXY=""
ARG HTTPS_PROXY=""
ARG NO_PROXY=""

ENV HTTP_PROXY=$HTTP_PROXY
ENV HTTPS_PROXY=$HTTPS_PROXY
ENV NO_PROXY=$NO_PROXY
ENV http_proxy=$HTTP_PROXY
ENV https_proxy=$HTTPS_PROXY
ENV no_proxy=$NO_PROXY

COPY . /src
WORKDIR /src/rsdhcp
RUN cargo build --release

FROM debian:bookworm AS environment

ARG HTTP_PROXY=""
ARG HTTPS_PROXY=""
ARG NO_PROXY=""

ENV HTTP_PROXY=$HTTP_PROXY
ENV HTTPS_PROXY=$HTTPS_PROXY
ENV NO_PROXY=$NO_PROXY
ENV http_proxy=$HTTP_PROXY
ENV https_proxy=$HTTPS_PROXY
ENV no_proxy=$NO_PROXY

RUN apt-get update && apt-get install -y \
      libssl3 && \
    rm -rf /var/lib/apt/lists/*

ENV HTTP_PROXY=
ENV HTTPS_PROXY=
ENV NO_PROXY=
ENV http_proxy=
ENV https_proxy=
ENV no_proxy=

COPY --from=build /src/rsdhcp/target/release/rsdhcp /usr/bin/rsdhcp
CMD ["-c", "/rsdhcp.yaml"]
ENTRYPOINT ["rsdhcp"]
