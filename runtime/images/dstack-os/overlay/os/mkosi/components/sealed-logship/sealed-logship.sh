# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash disable=SC2034
# Sealed debug variant only (scripts/build-components.sh adds it when
# SEALED_IMAGE_VARIANT=debug). Builds the container log exporter from
# os/sealed/logship with the pinned Go toolchain from versions.env.
COMPONENT_NAME=sealed-logship
COMPONENT_CACHE_PATHS=(component-stages/sealed-logship)
COMPONENT_ROOTFS_TREES=(component-stages/sealed-logship)
COMPONENT_KERNEL_TREES=()

component_cache_key() {
    key_file "$COMPONENT_PATH/sealed-logship-build.sh" \
      "$COMPONENT_PATH/sealed-logship.service" \
      "$COMPONENT_PATH/82-dstack-sealed-debug.preset"
    key_tree os/sealed/logship
    key_tools go
}

component_build() {
    "$COMPONENT_PATH/sealed-logship-build.sh" "$WORK/component-stages/sealed-logship"
}
