ARG ELIXIR_IMAGE=hexpm/elixir:1.20.3-erlang-29.0.5-debian-bookworm-20260824-slim@sha256:d0e7ade81190dda2517d441797f8ec4c36226742cc0d2789084b2d1ffbb457d8
ARG RUST_IMAGE=rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922
ARG RUNTIME_IMAGE=debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

FROM ${RUST_IMAGE} AS rust_toolchain

FROM ${ELIXIR_IMAGE} AS builder_base

ENV LANG=C.UTF-8 \
    MIX_ENV=prod

RUN apt-get update \
    && apt-get install --yes --no-install-recommends build-essential ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

RUN mix local.hex --force && mix local.rebar --force

COPY mix.exs mix.lock ./
COPY config ./config
RUN mix deps.get --only prod && mix deps.compile

COPY lib ./lib
COPY native ./native
COPY rel ./rel
COPY checksum-Elixir.Derpex.Crypto.Native.exs ./

FROM builder_base AS builder_precompiled
# A private repository's release assets cannot be fetched anonymously, so a
# tagged image build downloads them with the workflow's token into
# native-artifacts/ and the compile takes them from the rustler_precompiled
# cache instead of the network. With the directory empty, the compile falls
# back to downloading from the configured base URL.
COPY native-artifacts /build/native-artifacts
ENV RUSTLER_PRECOMPILED_GLOBAL_CACHE_PATH=/build/native-artifacts
RUN mix compile --warnings-as-errors && mix release derpex

FROM builder_base AS builder_source
COPY --from=rust_toolchain /usr/local/cargo /usr/local/cargo
COPY --from=rust_toolchain /usr/local/rustup /usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo \
    RUSTUP_HOME=/usr/local/rustup \
    PATH=/usr/local/cargo/bin:${PATH} \
    DERPEX_BUILD=1
RUN mix compile --warnings-as-errors && mix release derpex

FROM ${RUNTIME_IMAGE} AS runtime_base

ENV LANG=C.UTF-8 \
    HOME=/opt/derpex \
    ERL_CRASH_DUMP=/dev/null \
    ERL_CRASH_DUMP_SECONDS=0

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates libncurses6 libsctp1 libssl3 libstdc++6 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 derpex \
    && useradd --uid 10001 --gid derpex --home-dir /opt/derpex --shell /usr/sbin/nologin derpex

WORKDIR /opt/derpex
EXPOSE 443/tcp 3478/udp
USER derpex

FROM runtime_base AS runtime_source
COPY --from=builder_source --chown=derpex:derpex /build/_build/prod/rel/derpex ./
ENTRYPOINT ["/opt/derpex/bin/derpex"]
CMD ["start"]

FROM runtime_base AS runtime
COPY --from=builder_precompiled --chown=derpex:derpex /build/_build/prod/rel/derpex ./
ENTRYPOINT ["/opt/derpex/bin/derpex"]
CMD ["start"]
