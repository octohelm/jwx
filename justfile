# Go 工具链入口
mod go "tool/go/justfile"

[group('meta')]
default:
    @just --list --list-submodules
