# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

set -eu
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$source_dir/../.." && pwd)
output_dir=${1:?Specify an output directory outside the source tree}
mkdir -p "$output_dir"
output_dir=$(CDPATH= cd -- "$output_dir" && pwd)
case "$output_dir/" in "$repo_dir/"*) exit 1;; esac
flags='--target=arm-none-eabi -mcpu=cortex-r4 -mthumb -mrestrict-it -mfloat-abi=soft -mno-unaligned-access -Wno-missing-multilib -Oz -ffreestanding -fno-builtin -fno-stack-protector -fno-unwind-tables -fno-asynchronous-unwind-tables -ffunction-sections -Wall -Wextra -Werror'
"${LLVM_BIN:+$LLVM_BIN/}clang" $flags -I"$source_dir/../../src/common" -c "$source_dir/native_departure.c" -o "$output_dir/departure.o"
"${LLVM_BIN:+$LLVM_BIN/}ld.lld" -T "$source_dir/departure.ld" --no-undefined "$output_dir/departure.o" -o "$output_dir/departure.elf"
"${LLVM_BIN:+$LLVM_BIN/}llvm-objcopy" -O binary --only-section=.text "$output_dir/departure.elf" "$output_dir/departure.bin"
"${LLVM_BIN:+$LLVM_BIN/}llvm-nm" --defined-only --print-size --numeric-sort "$output_dir/departure.elf" > "$output_dir/departure.symbols"
