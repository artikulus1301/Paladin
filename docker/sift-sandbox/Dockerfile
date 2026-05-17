# SIFT Sandbox — Isolated forensic analysis container
# Based on Ubuntu 22.04 with SIFT forensic tools
# Security: no-new-privileges, read-only rootfs, network:none
FROM ubuntu:22.04

LABEL maintainer="paladin-security"
LABEL description="SIFT forensic analysis sandbox for Paladin 2.0"

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8

# ── Install SIFT forensic tools ──────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core utilities
    coreutils findutils file binutils \
    # Forensic tools
    sleuthkit \
    volatility3 \
    tshark \
    foremost \
    # String analysis
    strings \
    # Python for scripting tools
    python3 python3-pip \
    # Hash tools
    md5deep \
    ssdeep \
    # Registry analysis
    chntpw \
    # Timeline tools
    plaso \
    && rm -rf /var/lib/apt/lists/*

# ── Install Python forensic packages ─────────────────────────────────────────
RUN pip3 install --no-cache-dir \
    analyzeMFT \
    python-registry \
    yara-python \
    pefile \
    oletools \
    hindsight

# ── Create non-root user ─────────────────────────────────────────────────────
RUN groupadd -r siftuser && useradd -r -g siftuser -d /home/siftuser -s /bin/bash siftuser
RUN mkdir -p /home/siftuser /evidence /cases /output \
    && chown -R siftuser:siftuser /home/siftuser /cases /output

# Evidence is mounted read-only — this is just the mount point
VOLUME ["/evidence", "/cases", "/output"]

USER siftuser
WORKDIR /cases

# Container stays alive via sleep — commands run via docker exec
CMD ["sleep", "infinity"]
