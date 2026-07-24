# Linux Security Audit Tool — container image
#
# Build:
#   docker build -t security-audit .
#
# Run (mount the host filesystem read-only so the tool can audit the
# REAL host it's deployed on, not just the container's own filesystem):
#   docker run --rm --pid=host --network=host \
#     -v /:/host:ro \
#     -v /etc:/etc:ro \
#     security-audit --format text
#
# Note: auditing a live host's users/files/network from inside a
# container has real limits (namespaces isolate PIDs, network, mounts).
# For full-fidelity host auditing, running the tool natively on the
# host (via pip or the .pyz) is more accurate. This image is best used
# to audit the container's own filesystem/config, or as a portable way
# to ship the tool to a machine without pre-installing Python.

FROM python:3.12-slim

# Common CLI tools the checks rely on (all optional — checks degrade
# gracefully if a tool is missing, but installing them gives full
# coverage out of the box).
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    net-tools \
    findutils \
    procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY securityaudit/ ./securityaudit/
COPY pyproject.toml README.md ./

RUN pip install --no-cache-dir .

ENTRYPOINT ["security-audit"]
CMD ["--format", "text"]
