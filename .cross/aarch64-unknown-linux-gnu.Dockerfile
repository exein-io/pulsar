FROM ghcr.io/cross-rs/aarch64-unknown-linux-gnu:main
RUN dpkg --add-architecture arm64 && \
    ln -snf /usr/share/zoneinfo/Europe/Rome /etc/localtime && echo Europe/Rome > /etc/timezone \
    && apt update \
    && apt install -y \
        lsb-release \
        wget \
        software-properties-common \
        gnupg \
        libssl-dev:arm64 \
        libsqlite3-dev:arm64 \
    && wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && ./llvm.sh 17 \
    && ln -s /usr/bin/clang-17 /usr/bin/clang \
    && ln -s /usr/bin/llvm-strip-17 /usr/bin/llvm-strip
