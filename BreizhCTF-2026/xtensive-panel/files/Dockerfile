ARG QEMU_TAG=esp-develop-9.2.2-20250817

FROM debian:forky AS qemu-builder
ARG QEMU_TAG

RUN apt-get update -y && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  ca-certificates \
  g++ \
  gcc \
  git \
  libgcrypt20-dev \
  libglib2.0-dev \
  libpixman-1-dev \
  libslirp-dev \
  make \
  meson \
  ninja-build \
  pkgconf \
  python3 \
  python3-venv \
  wget \
  zlib1g-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY --chmod=755 ./get_qemu.sh .
RUN BUILD_DIR="/opt/qemu" QEMU_TAG="$QEMU_TAG" ./get_qemu.sh

FROM debian:forky
RUN apt-get update -y && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  libgcrypt20 \
  libglib2.0-0t64 \
  libncursesw6 \
  libpixman-1-0 \
  libslirp0 \
  libtinfo6 \
  socat \
  zlib1g \
 && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash ctf

WORKDIR /home/ctf/app

COPY --from=qemu-builder --chown=root:root --chmod=555 /opt/qemu/bin/qemu-system-xtensa .
COPY --from=qemu-builder --chown=ctf:ctf /opt/qemu/share/qemu/ ./qemu/share/qemu/
COPY --chown=ctf:ctf --chmod=444 ./qemu_efuse.bin .
COPY --chown=ctf:ctf --chmod=644 ./qemu_flash.bin .
COPY --chown=ctf:ctf --chmod=755 ./run.sh .

RUN chmod 555 /home/ctf/app

USER ctf
EXPOSE 1337
CMD ["socat", "tcp-l:1337,reuseaddr,fork", "EXEC:\"bash run.sh\""]
