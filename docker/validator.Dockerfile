ARG RELEASE=jammy
FROM ubuntu:${RELEASE} AS builder

ARG PACKAGE
ARG PATCH_FILE=patch.diff

RUN sed -i 's/^# deb-src /deb-src /' /etc/apt/sources.list
RUN apt-get update && apt-get install -y build-essential devscripts git ca-certificates

COPY ${PATCH_FILE} /patch.diff

RUN apt-get build-dep -y ${PACKAGE}
RUN apt-get source ${PACKAGE}

WORKDIR /build
RUN srcdir=$(find . -maxdepth 1 -type d -name "${PACKAGE}-*" | head -n1) && \
    if [ -s "/patch.diff" ]; then git -C "$srcdir" apply "/patch.diff"; fi && \
    cd "$srcdir" && dpkg-buildpackage -us -uc

RUN mkdir -p /debs && cp -v /build/*.deb /debs/

FROM ubuntu:${RELEASE} AS runtime
ARG PACKAGE

# Create non-root user for security
RUN groupadd -r secpatch && useradd -r -g secpatch -u 1000 secpatch

COPY --from=builder /debs /debs
COPY entrypoint.sh /entrypoint.sh

# Install packages and clean up
RUN apt-get update && apt-get install -y /debs/*.deb && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Set up directories and permissions
RUN mkdir -p /out/artifacts && \
    chown -R secpatch:secpatch /out && \
    chmod +x /entrypoint.sh

# Switch to non-root user
USER secpatch

ENTRYPOINT ["/entrypoint.sh"]
