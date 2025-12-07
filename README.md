# libssha — Embeddable SSH Agent Library (C++20)

A compact, modular, and extensible SSH agent implementation in C++20 compatible with the OpenSSH agent protocol.

## Highlights
- Embeddable library providing SSH agent server/session logic.
- Implements latest draft of the [OpenSSH agent protocol](https://datatracker.ietf.org/doc/draft-ietf-sshm-ssh-agent/12/).
- Modular key/provider architecture (RSA, ECDSA, ED25519, ED448).
- Extension points for custom policies and messages.
- Unit and integration tests with coverage support on Linux.
- Example providers implemented using Botan (under `src/providers/botan`). This library is using Botan 3.0+.
- This library was tested on Debian 13 (GCC 14.2) and MSVC 19.36 (Visual Studio 2022).

## Quick Start
- Requirements: a C++20 toolchain, `meson` and `ninja`, and the Botan library for the included key provider implementation.
- When building on Windows, you may need to install Botan via conan or vcpkg.

## Build Instructions
On Linux you can build the library in stadard way using `meson` and `ninja`, as follows:
```bash
git clone https://github.com/michal-pod/libssha.git
cd libssha
meson setup build
meson compile -C build
```

Integration tests can be run using:
```bash
meson test -C build
```

Code coverage can be generated using standard meson coverage tooling.

## Repository Layout
- `src/` — library implementation by subsystem (`agent/`, `key/`, `messages/`, `extensions/`, `providers/`, `utils/`).
- `include/` — library headers.
- `examples/` — functional example agents for testing and demonstration.
- `tests/` — unit and integration tests with test-data fixtures in `test-data/`.
- `scripts/` — helper scripts such as `generate_coverage.sh`.

## Usage Examples
- Run the example agent (built under `build/examples/test-agent`):
```bash
# run from repository root
./build/examples/test-agent
```
- To use the library in your own project, easiest way is to add it as a subproject in your `meson.build`. If you don't use meson, you can create for example in CMake a target that builds the library from source files in `src/` and includes headers from `include/`.


## Projects using this library
- SKYM - SSH KeY Manager - SSH agent for Windows with GUI, using libssha as the backend library - I'm preparing a separate repository for this project.

## Supported Key Types & Providers
- RSA, ECDSA (P-256/P-384/P-521), ED25519, ED448.
- Provider abstraction; example Botan provider in `src/providers/botan/`.

## Extensions & Policies
- Extension points are implemented under `src/extensions/` and `include/libssha/extensions/`.
- Provided extensions: `openssh-session-bind`, `openssh-restrict-destination`.

## Contributing
- Fork and open a pull request with a clear description and tests for new behavior.
- Run unit and integration tests (at least on Linux) before submitting.
- Follow existing code style (header/source pairing, small focused files, C++20).

## Notes & Known Limitations
- Smart card support is not implemented yet.
- Coverage tooling is validated on Linux; adjust scripts for other OSes.
- Integration tests are scripted and tested only on Linux.

## Contact & License
- See `LICENSE.md` for license terms.
- For questions or contributions, open an issue or PR on the repository.