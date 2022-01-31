FROM rust:1.58 AS builder

RUN cargo install wasm-pack && \
    apt-get update && \
    apt-get install -y binaryen
    
WORKDIR /usr/src
COPY . .

WORKDIR /usr/src/fort-rs-wasm
RUN wasm-pack build --target web

FROM nginx:alpine
COPY --from=builder \
    /usr/src/fort-rs-wasm/index.html \
    /usr/src/fort-rs-wasm/index.js \
    /usr/share/nginx/html/
COPY --from=builder \
    /usr/src/fort-rs-wasm/pkg \
    /usr/share/nginx/html/pkg/
