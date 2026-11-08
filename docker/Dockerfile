FROM --platform=linux/amd64 debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 gcc g++ make cmake binutils git libc6-dev autoconf automake libtool \
    bison flex pkg-config libonig-dev clang llvm ca-certificates \
    && rm -rf /var/lib/apt/lists/*
ENV LANG=C LC_ALL=C TZ=UTC
USER 1000:1000
WORKDIR /work

