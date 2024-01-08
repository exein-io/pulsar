FROM ghcr.io/cross-rs/riscv64gc-unknown-linux-gnu:main
RUN dpkg --add-architecture riscv64 && \
    ln -snf /usr/share/zoneinfo/Europe/Rome /etc/localtime && echo Europe/Rome > /etc/timezone \
    && apt update \
    && apt install -y \
        lsb-release \
        wget \
        software-properties-common \
        gnupg \
        libssl-dev:riscv64 \
        libsqlite3-dev:riscv64 \
    && wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && ./llvm.sh 17 \
    && ln -s /usr/bin/clang-17 /usr/bin/clang \
    && ln -s /usr/bin/llvm-strip-17 /usr/bin/llvm-strip
