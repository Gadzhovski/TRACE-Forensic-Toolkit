# Every tool the Linux-only test-image builders use (tools/testdata/build/),
# for building test_images/built on Windows or macOS:
#     python tools/testdata/build/docker_build.py
# The same packages Linux CI installs (.github/workflows/tests.yml).
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
      python3 python3-venv python3-pip ca-certificates curl git kmod \
      busybox-static zstd xz-utils bzip2 pbzip2 lz4 cpio gdisk fdisk \
      btrfs-progs mdadm cryptsetup-bin lvm2 dosfstools mtools e2fsprogs \
      squashfs-tools erofs-utils udftools genisoimage hfsutils mtd-utils \
      util-linux-extra genromfs u-boot-tools libubootenv-tool \
      android-sdk-libsparse-utils qemu-utils afflib-tools \
      build-essential autoconf automake libtool pkg-config uuid-dev \
      liblz4-dev liblzo2-dev libucl-dev zlib1g-dev \
      android-libbase-dev android-liblog-dev android-libsparse-dev \
      android-libext4-utils-dev android-libcutils-dev \
      android-libboringssl-dev \
      qemu-system-x86 linux-image-generic zfsutils-linux \
    && apt-get install -y -qq --no-install-recommends \
      "linux-modules-extra-$(ls /lib/modules | sort -V | tail -1)" \
    && rm -rf /var/lib/apt/lists/*
RUN python3 -m venv /opt/lfs && /opt/lfs/bin/pip install -q littlefs-python==0.19.0
