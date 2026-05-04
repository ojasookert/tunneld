FROM rust:1.95-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc-aarch64-linux-gnu \
        gcc-mingw-w64-x86-64 \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add \
        x86_64-unknown-linux-gnu \
        aarch64-unknown-linux-gnu \
        x86_64-pc-windows-gnu

ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --target x86_64-unknown-linux-gnu \
 && cargo build --release --target aarch64-unknown-linux-gnu \
 && cargo build --release --target x86_64-pc-windows-gnu \
 && strip target/x86_64-unknown-linux-gnu/release/tunneld \
 && aarch64-linux-gnu-strip target/aarch64-unknown-linux-gnu/release/tunneld \
 && x86_64-w64-mingw32-strip target/x86_64-pc-windows-gnu/release/tunneld.exe

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/x86_64-unknown-linux-gnu/release/tunneld /usr/local/bin/tunneld

RUN mkdir -p /dist
COPY --from=builder /build/target/x86_64-unknown-linux-gnu/release/tunneld   /dist/tunneld-linux-x86_64
COPY --from=builder /build/target/aarch64-unknown-linux-gnu/release/tunneld  /dist/tunneld-linux-aarch64
COPY --from=builder /build/target/x86_64-pc-windows-gnu/release/tunneld.exe  /dist/tunneld-windows-x86_64.exe

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/tunneld"]
CMD ["server"]
