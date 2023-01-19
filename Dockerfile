FROM registry.access.redhat.com/ubi9/ubi as builder

RUN dnf update -y && \
    dnf install gcc-c++ clang llvm-devel openssl-devel -y && \
    dnf clean all

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

ENV PATH $HOME/.cargo/bin:$PATH

WORKDIR /usr/src/app
COPY ./  /usr/src/app

RUN $HOME/.cargo/bin/cargo install --path . --locked --verbose

## runtime image configuration
FROM registry.access.redhat.com/ubi9-minimal:latest as runtime
RUN microdnf install -y openssl wget && microdnf clean all

## add the root certificate
RUN cd /etc/pki/ca-trust/source/anchors/ && \
    wget https://password.corp.redhat.com/RH-IT-Root-CA.crt && \
    update-ca-trust enable && \
    update-ca-trust extract

COPY config.json /etc/starproxy/config.json

COPY --from=builder /root/.cargo/bin/starproxy  /usr/local/bin/starproxy
ENTRYPOINT ["/usr/local/bin/starproxy"]
