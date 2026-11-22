# the native toolchain the Monad compiler shells out to
# (clang/llc/lld), the Boehm GC headers and static library the generated
# runtime links, and Node for smoke tests.
#
# The compiler itself is the installed nightly on ~/.monad/bin (see the
# README for the pinned revision). It is not built here: the project pins its
# motes to the compiler's revision, and `monad build`/`check`/`test` refuse
# to run when the two differ.
{ pkgs, lib, ... }:

{
  # The web profile is freestanding (no sysroot), so any clang with the wasm32
  # backend will do. nixpkgs' wrapped clang adds hardening flags the wasm
  # target rejects, so point Monad at the unwrapped one.
  env.MONAD_WEB_CC = "${pkgs.llvmPackages.clang-unwrapped}/bin/clang";

  packages = with pkgs; [
    git
    nodejs
    pkg-config
    llvm
    clang
    lld
    # The generated runtime (#include <gc.h>, -lgc) is a conservative-GC
    # runtime. enableStatic ships libgc.a, which monad's link step prefers.
    # The parentheses are load-bearing: a bare `boehmgc.override { ... }`
    # parses as two list elements.
    (boehmgc.override { enableStatic = true; })
  ];

  enterShell = ''
    # `monadup` installs the compiler here; the dev shell's PATH would
    # otherwise hide it.
    export PATH="$HOME/.monad/bin:$PATH"
    if ! command -v monad >/dev/null 2>&1; then
      echo "no 'monad' on PATH; install a nightly with 'monadup default'" >&2
    fi
  '';
}
