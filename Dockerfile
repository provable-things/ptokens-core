FROM rust:1.46

LABEL maintainer="Provable Things Ltd (info@provable.xyz)" \
    description="Serve as a base image layer to work with \
    pTokens command line interfaces."

WORKDIR /root

RUN mkdir core

COPY src core/src

COPY Cargo.* core/
