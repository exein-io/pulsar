FROM ghcr.io/cross-rs/riscv64gc-unknown-linux-gnu:main
RUN ln -snf /usr/share/zoneinfo/Europe/Rome /etc/localtime && echo Europe/Rome > /etc/timezone && \
    apt update && apt install -y \
    libssl-dev \
    lsb-release \
    wget \
    software-properties-common \
    gnupg && \
    wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && ./llvm.sh 16 && \
    ln -s /usr/bin/clang-16 /usr/bin/clang && \
    ln -s /usr/bin/llvm-strip-16 /usr/bin/llvm-strip
