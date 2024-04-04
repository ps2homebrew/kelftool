/*
 * Copyright (c) 2019 xfwcfw
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <limits>

#include "common.h"
#include "keystore.h"
#include "kelf.h"

uint8_t GSystemtype = SYSTEM_TYPE_PS2;
uint8_t GMGZones = REGION_ALL_ALLOWED;
uint16_t GFlags = HDR_PREDEF_KELF;
uint8_t GApplicationType = KELFTYPE_XOSDMAIN;

// TODO: implement load/save kelf header configuration for byte-perfect encryption, decryption

std::string getKeyStorePath()
{
#if defined(__linux__) || defined(__APPLE__)
    return std::string(getenv("HOME")) + "/PS2KEYS.dat";
#else
    return std::string(getenv("USERPROFILE")) + "\\PS2KEYS.dat";
#endif
}

int decrypt(int argc, char **argv)
{
    std::string KeyStoreEntry = "default";
    
    if (argc < 3) {
        printf("%s decrypt <input> <output> [flags]\n", argv[0]);
        return -1;
    }

    for (int x = 3; x < argc; x++)
    {
        if (!strncmp("--keys=", argv[x], strlen("--keys="))) {
            KeyStoreEntry = &argv[x][7];
        }
    }
    

    KeyStore ks;
    int ret = ks.Load("./PS2KEYS.dat", KeyStoreEntry);
    if (ret != 0) {
        // try to load keys from working directory
        ret = ks.Load(getKeyStorePath(), KeyStoreEntry);
        if (ret != 0) {
            printf("Failed to load keystore: %d - %s\n", ret, KeyStore::getErrorString(ret).c_str());
            return ret;
        }
    }

    Kelf kelf(ks);
    ret = kelf.LoadKelf(argv[1]);
    if (ret != 0) {
        printf("Failed to LoadKelf %d!\n", ret);
        return ret;
    }
    ret = kelf.SaveContent(argv[2]);
    if (ret != 0) {
        printf("Failed to SaveContent!\n");
        return ret;
    }

    return 0;
}

int encrypt(int argc, char **argv)
{
    std::string KeyStoreEntry = "default";
    int headerid = HEADER::INVALID;
    if (argc < 4) {
        printf("%s encrypt <headerid> <input> <output> [flags]\n", argv[0]);
        printf("<headerid>: fmcb, fhdb, mbr, dnasload\n");
        return -1;
    }

    if (strcmp("fmcb", argv[1]) == 0)
        headerid = HEADER::FMCB;

    if (strcmp("fhdb", argv[1]) == 0)
        headerid = HEADER::FHDB;

    if (strcmp("mbr", argv[1]) == 0)
        headerid = HEADER::MBR;

    if (strcmp("dnasload", argv[1]) == 0)
        headerid = HEADER::DNASLOAD;

    if (headerid == HEADER::INVALID) {
        printf("Invalid header: %s\n", argv[1]);
        return -1;
    }

    for (int x = 4; x < argc; x++)
    {
        if (!strncmp("--keys=", argv[x], strlen("--keys="))) {
            printf("- Custom keyset %s\n", &argv[x][7]);
            KeyStoreEntry = &argv[x][7];
        } else if (!strncmp("--systemtype=", argv[x], strlen("--systemtype="))) {
            const char* a = &argv[x][13];
            long t;
            if (!strcmp(a, "PS2")) {
                GSystemtype = SYSTEM_TYPE_PS2;
            } else if (!strcmp(a, "PSX")) {
                GSystemtype = SYSTEM_TYPE_PSX;
            } else if ((t = strtoul(a, NULL, 10)) <= std::numeric_limits<std::uint8_t>::max()) {
                GSystemtype = (uint8_t)t;
            }
        } else if (!strncmp("--kflags=", argv[x], strlen("--kflags="))) {
            const char* a = &argv[x][9];
            unsigned long t;
            if (!strcmp(a, "KELF")) {
                GFlags = HDR_PREDEF_KELF;
            } else if (!strcmp(a, "KIRX")) {
                GFlags = HDR_PREDEF_KIRX;
            } else if ((t = strtoul(a, NULL, 16)) <= std::numeric_limits<std::uint16_t>::max()) {
                GFlags = (uint16_t)t;
                if ((GFlags & HDR_FLAG4_1DES) && (GFlags & HDR_FLAG4_3DES)) {
                    printf(YELBOLD "WARNING: 0x%x specifies both Single and Triple DES. only one should be defined" DEFCOL "\n", t);
                }
            }

        } else if (!strncmp("--mgzone=", argv[x], strlen("--mgzone="))) {
            const char* a = &argv[x][9];
            long t;
            if ((t = strtoul(a, NULL, 16))<std::numeric_limits<std::uint8_t>::max()) {
                GMGZones = (uint8_t)t;
            }
        } else if (!strncmp("--apptype=", argv[x], strlen("--apptype="))) {
            const char* a = &argv[x][10];
            long t;
            if ((t = strtoul(a, NULL, 16)) <= std::numeric_limits<std::uint8_t>::max()) {
                GApplicationType = (uint8_t)t;
            }
        }
    }

#ifdef DEBUG
    printf(
    "GSystemtype 0x%x\n"
    "GMGZones 0x%x\n"
    "GFlags 0x%x\n"
    "GApplicationType 0x%x\n",
    GSystemtype,
    GMGZones,
    GFlags,
    GApplicationType);
#endif

    KeyStore ks;
    int ret = ks.Load("./PS2KEYS.dat", KeyStoreEntry);
    if (ret != 0) {
        // try to load keys from working directory
        ret = ks.Load(getKeyStorePath(), KeyStoreEntry);
        if (ret != 0) {
            printf("Failed to load keystore: %d - %s\n", ret, KeyStore::getErrorString(ret).c_str());
            return ret;
        }
    }

    Kelf kelf(ks);
    ret = kelf.LoadContent(argv[2], headerid);
    if (ret != 0) {
        printf("Failed to LoadContent!\n");
        return ret;
    }

    ret = kelf.SaveKelf(argv[3], headerid);
    if (ret != 0) {
        printf("Failed to SaveKelf!\n");
        return ret;
    }

    return 0;
}



int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("usage: %s <submodule> <args>\n", argv[0]);
        printf("Available submodules:\n");
        printf("\tdecrypt - decrypt and check signature of kelf files\n");
        printf("\tencrypt <headerid> - encrypt and sign kelf files <headerid>: fmcb, fhdb, mbr, dnasload\n");
        printf("\t\tfmcb     - for retail PS2 memory cards\n");
        printf("\t\tdnasload - for retail PS2 memory cards (PSX Whitelisted)\n");
        printf("\t\tfhdb     - for retail PS2 HDD (HDD OSD / BB Navigator)\n");
        printf("\t\tmbr      - for retail PS2 HDD (mbr injection).\n");
        printf("\t\t          Note: for mbr elf should load from 0x100000 and should be without headers:\n");
        printf("\t\t          readelf -h <input_elf> should show 0x100000 or 0x100008\n");
        printf("\t\t          $(EE_OBJCOPY) -O binary -v <input_elf> <headerless_elf>\n");
        return -1;
    }

    char *cmd = argv[1];
    argv[1]   = argv[0];
    argc--;
    argv++;

    if (strcmp("decrypt", cmd) == 0)
        return decrypt(argc, argv);
    else if (strcmp("encrypt", cmd) == 0)
        return encrypt(argc, argv);

    printf("Unknown submodule!\n");
    return -1;
}
