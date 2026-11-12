FROM public.ecr.aws/docker/library/rust:1.99-trixie AS builder

RUN mkdir -p /build/src/bin

RUN echo 'fn main() {}' > /build/src/main.rs
COPY Cargo.toml Cargo.lock /build/
WORKDIR /build
RUN cargo build --release --locked

COPY src /build/src
RUN cargo build --release --locked

FROM gcr.io/distroless/cc-debian13
COPY --from=builder /build/target/release/ecamo /usr/local/bin/
CMD ["/usr/local/bin/ecamo"]
