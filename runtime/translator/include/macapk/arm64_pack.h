// arm64_pack.h -- "Native arm64" packager that turns an arm64 Android
// .so into a Mach-O dylib wrapper without translating any instructions.
//
// The wrapper embeds the original ELF and exposes its dynamic exports
// as branch-through-pointer trampolines; the runtime ELF loader in
// libmacapk-bionic-shim maps + relocates + runs init_array when the
// wrapper's __mod_init_func fires.
//
// Replaces the old "lift arm64 to LLVM IR and back to arm64" approach
// for arm64 inputs.

#pragma once

#include <string>

#include "macapk/elf64_reader.h"

namespace macapk::translator {

int run_arm64_pack(const std::string& in_path,
                    const std::string& out_path,
                    const std::string& shim_dir,
                    bool verbose,
                    bool keep_ir,
                    const Elf64Image& img);

}  // namespace macapk::translator
