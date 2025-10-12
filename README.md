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
- Requirements: a C++20 toolchain, `cmake`, `make` or `ninja`, and the Botan library for the included key provider implementation.
- When building on Windows, set the `BOTAN_ROOT` CMake cache variable to the root directory of your Botan installation. Remember botan build should match build settings (e.g. MSVC version, Debug/Release). Using for example debug build of Botan with release build of libssha will likely lead to crashes.

## Build (out-of-tree)
```bash
mkdir -p build
cd build
cmake ..
cmake --build . -j$(nproc)
```

Run all tests
```bash
cd build
ctest -j
```

Run integration tests (scripted, tested only on Linux)
```bash
# from repository root
(cd build/tests/integration && ../../../tests/integration/tests.sh)
```

Generate coverage (Linux)
```bash
./scripts/generate_coverage.sh
```

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
- Use the library from your project by including `include/libssha` headers and linking the built library from `build/lib` (CMake target names are available in `CMakeLists.txt`).

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