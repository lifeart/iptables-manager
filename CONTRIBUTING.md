# Contributing to Traffic Rules

## Prerequisites

- [Rust](https://rustup.rs/) stable toolchain (managed via `rust-toolchain.toml`)
- [Node.js](https://nodejs.org/) 18+
- Platform-specific Tauri dependencies:
  - **macOS**: Xcode Command Line Tools
  - **Linux**: `libwebkit2gtk-4.1-dev`, `libappindicator3-dev`, `librsvg2-dev`, `patchelf`
  - **Windows**: Microsoft Visual Studio C++ Build Tools, WebView2

## Getting Started

```bash
# Clone the repository
git clone <repo-url>
cd iptables-manager

# Install frontend dependencies
npm install

# Run in development mode (starts Vite dev server + Tauri)
npm run dev

# Run Rust tests
npm test
# or directly:
cargo test --manifest-path src-tauri/Cargo.toml

# Generate TypeScript types from Rust structs
cargo test export_bindings --manifest-path src-tauri/Cargo.toml

# Lint
cargo clippy --manifest-path src-tauri/Cargo.toml
npx tsc --noEmit

# Build for production
npm run build
```

## Project Structure

- `src/` — Frontend (TypeScript, vanilla DOM, CSS)
- `src-tauri/` — Backend (Rust, Tauri 2.x)
- `docs/` — Architecture and UX specifications

See `docs/architecture/06-project-structure.md` for the full directory layout.

## Development Workflow

1. Read the relevant spec in `docs/` before implementing a feature.
2. Implement the Rust backend module with unit tests.
3. Run `cargo test` to verify.
4. Implement the frontend module.
5. Run `npx tsc --noEmit` to verify types.

## Testing

### Unit Tests (no SSH needed)
- Parser tests use fixture files in `src-tauri/tests/fixtures/`
- Run with `cargo test --manifest-path src-tauri/Cargo.toml`

### Integration Tests (requires Docker)
- See `docs/architecture/06-project-structure.md` for Docker container setup

## Code Style

- Rust: follow `cargo clippy` recommendations
- TypeScript: strict mode, no `any` types
- CSS: BEM naming, `@layer` for specificity management
