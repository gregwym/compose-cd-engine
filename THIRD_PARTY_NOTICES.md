# Third-party components

The approval service additionally installs hash-pinned python-fido2
(BSD-2-Clause core, Apache-2.0 HID components and MPL-2.0 public suffix data), cryptography (Apache-2.0 OR BSD-3-Clause), cffi (MIT), and
pycparser (BSD-3-Clause). Their wheel distributions include upstream license
texts in installed package metadata. Exact versions and distribution hashes
are recorded in requirements.txt. No private authenticator key is generated
or stored by the approval service.

The Python engine source is MIT-licensed. The image also contains separately
licensed software; the engine license does not relicense those components.

- [Python / Debian base](https://hub.docker.com/_/python): Python Software
  Foundation license and individual Debian package licenses. Existing notices
  remain in the base image, including `/usr/share/doc`.
- [Docker CLI](https://github.com/docker/cli) and
  [Compose](https://github.com/docker/compose): Apache-2.0 and dependency licenses.
- [Cosign v3.1.3](https://github.com/sigstore/cosign/tree/v3.1.3): Apache-2.0 and
  dependency licenses. Binaries are verified against pinned release checksums.

Release workflow Actions are referenced, not vendored. Image dependency versions
are pinned in Dockerfile; updating these pins requires a normal review and build.

Upstream project LICENSE/NOTICE texts are included under `third_party/` and in
`/usr/share/doc/compose-cd-engine/third_party/` in the runtime image.
