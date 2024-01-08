FROM ghcr.io/cross-rs/x86_64-unknown-linux-musl:main
RUN ln -snf /usr/share/zoneinfo/Europe/Rome /etc/localtime && echo Europe/Rome > /etc/timezone \
    && apt update \
    && apt install -y \
        lsb-release \
        wget \
        software-properties-common \
        gnupg \
        libssl-dev \
        libsqlite3-dev \
    && wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && ./llvm.sh 17 \
    && ln -s /usr/bin/clang-17 /usr/bin/clang \
    && ln -s /usr/bin/llvm-strip-17 /usr/bin/llvm-strip
