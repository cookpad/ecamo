FROM public.ecr.aws/docker/library/rust:1.57-bullseye as builder

RUN mkdir -p /build/src/bin

RUN echo 'fn main() {}' > /build/src/main.rs
COPY Cargo.toml Cargo.lock /build/
WORKDIR /build
RUN cargo build --release --locked

COPY src /build/src
RUN cargo build --release --locked

FROM gcr.io/distroless/cc-debian11
COPY --from=builder /build/target/release/ecamo /usr/local/bin/
CMD ["/usr/local/bin/ecamo"]
