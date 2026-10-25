# syntax=docker/dockerfile:1
FROM docker:28-cli@sha256:625d9431a9f54c5a2bc90f24f0e1c3d55b1349fd857dd85035f98c2c9acbdd4d AS docker-cli
FROM --platform=$BUILDPLATFORM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258 AS tools
ARG TARGETARCH
COPY config/cosign-checksums.txt /checksums.txt
RUN TARGETARCH="$TARGETARCH" python3 - <<'BUILD'
import hashlib, os, pathlib, urllib.request
arch = os.environ['TARGETARCH']
if arch not in ('amd64', 'arm64'): raise SystemExit('unsupported architecture')
name = 'cosign-linux-' + arch
expected = dict(line.split()[::-1] for line in pathlib.Path('/checksums.txt').read_text().splitlines())[name]
with urllib.request.urlopen('https://github.com/sigstore/cosign/releases/download/v3.1.3/' + name, timeout=120) as response:
    data = response.read()
if hashlib.sha256(data).hexdigest() != expected: raise SystemExit('Cosign checksum mismatch')
pathlib.Path('/cosign').write_bytes(data)
pathlib.Path('/cosign').chmod(0o755)
BUILD
FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker-cli /usr/local/libexec/docker/cli-plugins/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose
COPY --from=tools /cosign /usr/local/bin/cosign
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: -r /app/requirements.txt
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app
COPY receiver/ receiver/
COPY verifier/ verifier/
COPY runner/ runner/
COPY shared/ shared/
COPY management/ management/
COPY deployer/ deployer/
COPY authorization/ authorization/
COPY installer/ installer/
RUN chmod -R a+rX /app
COPY LICENSE THIRD_PARTY_NOTICES.md /usr/share/doc/compose-cd-engine/
COPY third_party/ /usr/share/doc/compose-cd-engine/third_party/
USER 10001:10001
CMD ["python3", "receiver/receiver.py", "--container"]
