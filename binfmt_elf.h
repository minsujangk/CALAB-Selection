//
// Created by ms.jang on 2019-11-25.
//

#ifndef CALAB_SELECTION_BINFMT_ELF_H
#define CALAB_SELECTION_BINFMT_ELF_H

#include <sys/user.h>
#include <linux/elf.h>
#include "prm_loader.h"

// 64-bit configuration for simplicity
#define elfhdr elf64_hdr
#define elf_phdr elf64_phdr

#define ELF_MIN_ALIGN PAGE_SIZE
#define ELF_PAGESTART(_v) ((_v) & ~(unsigned long)(ELF_MIN_ALIGN - 1))
#define ELF_PAGEOFFSET(_v) ((_v) & (ELF_MIN_ALIGN - 1))
#define ELF_PAGEALIGN(_v) (((_v) + ELF_MIN_ALIGN - 1) & ~(ELF_MIN_ALIGN - 1))

struct binfmt_elf
{
};

int load_elf_binary(struct exec_prm *);

#endif //CALAB_SELECTION_BINFMT_ELF_H
