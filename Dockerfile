FROM ubuntu:24.04

ARG TARGETARCH=x86_64

# Set noninteractive mode for apt-get
ENV DEBIAN_FRONTEND=noninteractive

# Set timezone
ENV TZ=Asia/Shanghai

# Install dependencies
RUN apt-get update && \
    apt-get install -y \
        bash git sudo jq curl wget gzip locales patch \
        build-essential cmake pkg-config lld ninja-build \
        binutils binutils-dev autoconf automake libtool libncurses5-dev libgdbm-dev libnss3-dev liblzma-dev zlib1g-dev libyaml-dev graphviz libgraphviz-dev \
        libicu-dev libcurl4-openssl-dev libssl-dev libsqlite3-dev ruby-dev libreadline-dev libffi-dev libbz2-dev libc++-dev libc++abi-dev libc6-dev libgcc-9-dev tzdata \
        libyaml-dev ca-certificates apt-transport-https gnupg neofetch texinfo tree gnuplot graphviz graphviz-dev tmux  && \
        ln -sf /usr/share/zoneinfo/$TZ /etc/localtime && \
        dpkg-reconfigure -f noninteractive tzdata

# Install secondary dependencies
RUN apt-get update && \
    apt-get install -y \
    lsb-release software-properties-common gnupg pixz

# Locale settings
RUN locale-gen en_US.UTF-8 && update-locale LANG=en_US.UTF-8

# Install llvm
RUN apt-get update && apt-get install -y lsb-release wget software-properties-common gnupg && \
    wget https://apt.llvm.org/llvm.sh && \
    chmod +x llvm.sh && \
    ./llvm.sh 21 all && \
    rm llvm.sh && \
    LLVM_BIN_DIR="/usr/lib/llvm-21/bin" && \
    MASTER_BIN="$LLVM_BIN_DIR/clang" && \
    if [ -f "$MASTER_BIN" ]; then \
        CMD="update-alternatives --install /usr/bin/clang clang $MASTER_BIN 100" && \
        for f in $LLVM_BIN_DIR/*; do \
            TOOL_NAME=$(basename "$f"); \
            if [ "$TOOL_NAME" != "clang" ] && [ -x "$f" ] && [ ! -d "$f" ]; then \
                CMD="$CMD --slave /usr/bin/$TOOL_NAME $TOOL_NAME $f"; \
            fi; \
        done && \
        eval "$CMD"; \
    else \
        echo "Error: $MASTER_BIN not found." && exit 1; \
    fi && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Install honggfuzz
# RUN git clone https://github.com/google/honggfuzz.git /tmp/honggfuzz && \
#     cd /tmp/honggfuzz && \
#     make -j$(nproc) && \
#     make -j$(nproc) install && \
#     rm -rf /tmp/honggfuzz

# Install Rust and casr
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \
    echo 'source $HOME/.cargo/env' >> ~/.bashrc
ENV PATH="/root/.cargo/bin:${PATH}"
RUN cargo install -F dojo casr

# Install Ruby
# RUN git clone https://github.com/rbenv/rbenv.git ~/.rbenv && \
    # cd ~/.rbenv && src/configure && make -j$(nproc) -C src && \
    # echo 'export PATH="$HOME/.rbenv/bin:$PATH"' >> ~/.bashrc && \
    # echo 'eval "$(rbenv init -)"' >> ~/.bashrc && \
    # . ~/.bashrc

# Initialize Git
RUN git config --global user.email "example@example.com" && \
    git config --global user.name "example"

# Add `ls` alias
RUN echo "alias ls='ls -F'" >> ~/.bashrc


RUN curl -LsSf https://astral.sh/uv/install.sh | sh && \
    /root/.local/bin/uv python install 3.12 

ENV PATH="/root/.local/bin:${PATH}"
ENV CMAKE_LIBRARY_PATH="/usr/lib/x86_64-linux-gnu"
    

# Clean the environment variables
ENV DEBIAN_FRONTEND=dialog


# For easy debug (tmux and pwndbg)
RUN cd /root && git clone --single-branch https://github.com/gpakosz/.tmux.git && \
    ln -s -f .tmux/.tmux.conf && \
    cp .tmux/.tmux.conf.local . && \
    git clone https://github.com/pwndbg/pwndbg.git /tmp/pwndbg && \
    cd /tmp/pwndbg && \
    git submodule update --init --recursive && \
    ./setup.sh


# Install later dependencies
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    bubblewrap rsync yasm

# Install Golang dependencies
RUN wget https://go.dev/dl/go1.25.1.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.25.1.linux-amd64.tar.gz && \
    rm go1.25.1.linux-amd64.tar.gz 

ENV PATH=$PATH:/usr/local/go/bin
ENV GOPATH=/go
ENV PATH=$PATH:$GOPATH/bin

RUN go install github.com/boyter/scc/v3@latest

# Fetch the published tool separately from the host workspace.
ARG HARNESSMINIMIZER_REF=main
RUN git init /root/HarnessMinimizer && \
    git -C /root/HarnessMinimizer remote add origin https://github.com/FuzzAnything/HarnessMinimizer.git && \
    git -C /root/HarnessMinimizer fetch --depth 1 --no-tags origin "$HARNESSMINIMIZER_REF" && \
    git -C /root/HarnessMinimizer checkout --detach FETCH_HEAD
WORKDIR /root/HarnessMinimizer

# Install the Python package and both external reducer programs into the image.
ARG ENGINE_BUILD_JOBS=2
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        openjdk-17-jdk-headless coreutils unzip zip && \
    rm -rf /var/lib/apt/lists/*
RUN mkdir -p .tools/bin && \
    curl -fL --retry 3 \
        https://github.com/bazelbuild/bazelisk/releases/download/v1.29.0/bazelisk-linux-amd64 \
        -o .tools/bin/bazelisk && \
    chmod +x .tools/bin/bazelisk

ENV VIRTUAL_ENV="/root/HarnessMinimizer/.venv"
ENV PATH="/root/HarnessMinimizer/.venv/bin:/root/HarnessMinimizer/.tools/bin:${PATH}"
RUN uv sync --frozen
RUN python tools/treereduce/install.py --jobs "$ENGINE_BUILD_JOBS"

# Keep the pinned upstream checkout, including its license and build files.
RUN mkdir -p .tools/perses && \
    git clone https://github.com/uw-pluverse/perses.git .tools/perses/source && \
    git -C .tools/perses/source checkout --detach 6c6ae0db20fa83b0f85a71ca447f0c4d5e056bd2 && \
    python tools/perses/install.py --source .tools/perses/source --jobs "$ENGINE_BUILD_JOBS" && \
    (cd .tools/perses/source && bazelisk shutdown)

ENV HARNESSMINIMIZER_TREEREDUCE="/root/HarnessMinimizer/.tools/bin/treereduce-c" \
    HARNESSMINIMIZER_PERSES_JAR="/root/HarnessMinimizer/.tools/perses/perses_deploy.jar"
RUN harnessminimizer --help >/dev/null && \
    "$HARNESSMINIMIZER_TREEREDUCE" --harnessminimizer-supervisor-version && \
    java -jar "$HARNESSMINIMIZER_PERSES_JAR" --help >/dev/null

ENV DEBUGINFOD_URLS="" \
    ASAN_SYMBOLIZER_PATH="/usr/lib/llvm-21/bin/llvm-symbolizer" \
    UBSAN_SYMBOLIZER_PATH="/usr/lib/llvm-21/bin/llvm-symbolizer"
