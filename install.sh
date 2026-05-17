#!/bin/sh
# capframe installer — https://capframe.ai
# Usage:
#   curl -fsSL https://capframe.ai/install | sh
#   curl -fsSL https://capframe.ai/install | sh -s -- --version v0.1.0
#
# Honors:
#   CAPFRAME_VERSION    pin a release (default: latest)
#   CAPFRAME_INSTALL    install dir (default: $HOME/.capframe)
#   CAPFRAME_NO_MODIFY_PATH=1   skip shell rc edits
#
set -eu

REPO="capframe/capframe"
INSTALL_DIR="${CAPFRAME_INSTALL:-$HOME/.capframe}"
VERSION="${CAPFRAME_VERSION:-latest}"

GREEN=$(printf '\033[32m'); BOLD=$(printf '\033[1m')
DIM=$(printf '\033[2m');    RED=$(printf '\033[31m'); RESET=$(printf '\033[0m')
info()  { printf '%s::%s %s\n'   "$GREEN" "$RESET" "$*"; }
warn()  { printf '%s!!%s  %s\n'  "$RED"   "$RESET" "$*" >&2; }
fatal() { warn "$*"; exit 1; }

detect_target() {
    os=$(uname -s)
    arch=$(uname -m)
    case "$os" in
        Darwin)  os_tag="apple-darwin" ;;
        Linux)   os_tag="unknown-linux-gnu" ;;
        MINGW*|MSYS*|CYGWIN*) fatal "Windows: use install.ps1 instead (https://capframe.ai/install.ps1)" ;;
        *)       fatal "Unsupported OS: $os" ;;
    esac
    case "$arch" in
        x86_64|amd64)        arch_tag="x86_64" ;;
        arm64|aarch64)       arch_tag="aarch64" ;;
        *)                   fatal "Unsupported arch: $arch" ;;
    esac
    printf '%s-%s' "$arch_tag" "$os_tag"
}

resolve_version() {
    if [ "$VERSION" = "latest" ]; then
        curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
            | sed -n 's/.*"tag_name":[[:space:]]*"\(.*\)".*/\1/p' \
            | head -n1
    else
        printf '%s' "$VERSION"
    fi
}

verify_sha256() {
    file="$1"; expected="$2"
    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "$file" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        actual=$(shasum -a 256 "$file" | awk '{print $1}')
    else
        fatal "neither sha256sum nor shasum found — refusing to install unverified binary"
    fi
    [ "$actual" = "$expected" ] || fatal "checksum mismatch (expected $expected, got $actual)"
}

update_shell_rc() {
    bin_dir="$1"
    line="export PATH=\"$bin_dir:\$PATH\" # added by capframe installer"
    for rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
        [ -f "$rc" ] || continue
        if ! grep -Fq "added by capframe installer" "$rc" 2>/dev/null; then
            printf '\n%s\n' "$line" >> "$rc"
            info "updated $rc"
        fi
    done
    fish_rc="$HOME/.config/fish/config.fish"
    if [ -f "$fish_rc" ] && ! grep -Fq "added by capframe installer" "$fish_rc"; then
        printf '\nfish_add_path %s # added by capframe installer\n' "$bin_dir" >> "$fish_rc"
        info "updated $fish_rc"
    fi
}

main() {
    command -v curl >/dev/null 2>&1 || fatal "curl is required"
    command -v tar  >/dev/null 2>&1 || fatal "tar is required"

    target=$(detect_target)
    ver=$(resolve_version)
    [ -n "$ver" ] || fatal "could not resolve release version"

    info "${BOLD}Installing capframe $ver${RESET} for $target"

    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT INT TERM

    tarball="capframe-$ver-$target.tar.gz"
    base_url="https://github.com/$REPO/releases/download/$ver"

    info "downloading $tarball"
    curl -fsSL "$base_url/$tarball"            -o "$tmpdir/$tarball"
    curl -fsSL "$base_url/$tarball.sha256"     -o "$tmpdir/$tarball.sha256"

    expected=$(awk '{print $1}' "$tmpdir/$tarball.sha256")
    info "verifying sha256"
    verify_sha256 "$tmpdir/$tarball" "$expected"

    bin_dir="$INSTALL_DIR/bin"
    mkdir -p "$bin_dir"
    tar -xzf "$tmpdir/$tarball" -C "$tmpdir"
    mv "$tmpdir/capframe" "$bin_dir/capframe"
    chmod +x "$bin_dir/capframe"

    info "installed to ${BOLD}$bin_dir/capframe${RESET}"

    if [ "${CAPFRAME_NO_MODIFY_PATH:-0}" != "1" ]; then
        case ":$PATH:" in
            *":$bin_dir:"*) info "$bin_dir already on PATH" ;;
            *) update_shell_rc "$bin_dir"
               printf '%s   open a new shell, or run: %sexport PATH="%s:$PATH"%s\n' "$DIM" "$BOLD" "$bin_dir" "$RESET" ;;
        esac
    fi

    cat <<EOF

  ${GREEN}capframe is ready.${RESET}

  Quick start:
    ${BOLD}capframe find --help${RESET}      map your agent's tool surface
    ${BOLD}capframe bind --help${RESET}      mint a capability token
    ${BOLD}capframe guard --help${RESET}     run the runtime sentry

  Docs:    https://capframe.ai/docs
  Discord: https://capframe.ai/discord

EOF
}

main "$@"
