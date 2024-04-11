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
#ifndef __KELF_H__
#define __KELF_H__

#include "keystore.h"

#define KELF_ERROR_INVALID_DES_KEY_COUNT       -1
#define KELF_ERROR_INVALID_HEADER_SIGNATURE    -2
#define KELF_ERROR_INVALID_BIT_TABLE_SIZE      -3
#define KELF_ERROR_INVALID_BIT_TABLE_SIGNATURE -4
#define KELF_ERROR_INVALID_ROOT_SIGNATURE      -5
#define KELF_ERROR_INVALID_CONTENT_SIGNATURE   -6
#define KELF_ERROR_UNSUPPORTED_FILE            -6

#define SYSTEM_TYPE_PS2 0 // same for COH (arcade)
#define SYSTEM_TYPE_PSX 1

enum HEADER {
    INVALID = -1,
    FMCB = 0,
    FHDB,
    MBR,
    DNASLOAD,
};

static uint8_t USER_HEADER_FMCB[16] = {0x01, 0x00, 0x00, 0x01, 0x00, 0x03, 0x00, 0x4A, 0x00, 0x01, 0x02, 0x19, 0x00, 0x00, 0x00, 0x56};
static uint8_t USER_HEADER_FHDB[16] = {0x01, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00, 0x4A, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x1B};
static uint8_t USER_HEADER_MBR[16]  = {0x01, 0x00, 0x00, 0x04, 0x00, 0x02, 0x01, 0x57, 0x07, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2A};
static uint8_t USER_HEADER_DNASLOAD[16]  = {0x01, 0x00, 0x00, 0x04, 0x00, 0x06, 0x00, 0x4A, 0x00, 0x0E, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02};

static uint8_t USER_HEADER_NAMCO_SECURITY_DONGLE_BOOTFILE[16]  = {0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00};

static uint8_t USER_Kbit_MBR[16]  = {0x6f, 0x6f, 0x40, 0x07, 0x59, 0x23, 0x2a, 0x48, 0x03, 0x45, 0xf6, 0xee, 0x9f, 0x24, 0xfe, 0xf1};
static uint8_t USER_Kbit_FHDB[16] = {0xcc, 0x3a, 0x5a, 0x4e, 0x5c, 0x7f, 0x7c, 0x23, 0xb7, 0x5e, 0x9b, 0xf6, 0xa0, 0x44, 0x4e, 0x05};
static uint8_t USER_Kbit_FMCB[16] = {0x24, 0x25, 0x1D, 0x05, 0xd1, 0x5e, 0x2d, 0x7d, 0x94, 0x3f, 0x4a, 0x30, 0x3f, 0x28, 0x24, 0xdb};

#pragma pack(push, 1)
struct KELFHeader
{
    uint8_t UserDefined[16];
    uint32_t ContentSize; // balika: Sometimes not...
    uint16_t HeaderSize;
    uint8_t SystemType;
    uint8_t ApplicationType;
    uint16_t Flags;
    uint16_t BitCount;
    uint8_t MGZones;
    uint8_t gap[3]; // always zero
    // struct IDList
    // {
    //     uint64_t iLinkID;
    //     uint64_t consoleID;
    // } Blocks[16];
};

// possible BitBlock.Flags. Other bit flags should be unset
#define HDR_FLAG0_BLACKLIST 0x1    // Unset. if set then BitCount should be non-zero, and header will change its size
#define HDR_FLAG1_WHITELIST 0x2    // Unset. maybe whitelist? ICVPS2 ??
#define HDR_FLAG2           0x4    // Set. ??
#define HDR_FLAG3           0x8    // Set. ??
#define HDR_FLAG4_1DES      0x10   // Set in kirx. HDR_FLAG4_3DES should be unset. Represents Single DES encryption
#define HDR_FLAG4_3DES      0x20   // Set in kelf. HDR_FLAG4_1DES should be unset. Represents Triple DES encryption
#define HDR_FLAG6           0x40   // Unset. ??
#define HDR_FLAG7           0x80   // Unset. ??
#define HDR_FLAG8           0x100  // Unset. ??
#define HDR_FLAG9           0x200  // Unset. ??
#define HDR_FLAG10          0x400  // Set. ??
#define HDR_FLAG11          0x800  // Unset. ??
#define HDR_FLAG12          0x1000 // Unset. ??
#define HDR_FLAG13          0x2000 // Unset. ??
#define HDR_FLAG14          0x4000 // Unset. ??
#define HDR_FLAG15          0x8000 // Unset. ??
#define HDR_PREDEF_KELF 0x022c
#define HDR_PREDEF_KIRX 0x021c

// MGZones region flags. If unset - blocked in that region
#define REGION_JP   0x1  // Japan
#define REGION_NA   0x2  // North America
#define REGION_EU   0x4  // Europe
#define REGION_AU   0x8  // Australia
#define REGION_ASIA 0x10 // Asia
#define REGION_RU   0x20 // Russia
#define REGION_CH   0x40 // China
#define REGION_MX   0x80 // Mexico
#define REGION_ALL_ALLOWED 0xFF

#define KELFTYPE_DISC_WOOBLE 0
#define KELFTYPE_XOSDMAIN 1
#define KELFTYPE_DVDPLAYER_KIRX 5
#define KELFTYPE_DVDPLAYER_KELF 7
#define KELFTYPE_EARLY_MBR 11

struct BitTable
{
    uint32_t HeaderSize;
    uint8_t BlockCount;
    uint8_t gap[3]; // always zero

    struct BitBlock
    {
        uint32_t Size;
        uint32_t Flags; // bits 2-8 always zero
        uint8_t Signature[8];
    } Blocks[256];
};

// possible BitBlock Flags.
#define BIT_BLOCK_ENCRYPTED 0x1
#define BIT_BLOCK_SIGNED    0x2

#pragma pack(pop)

class Kelf
{
    KeyStore ks;
    std::string Kbit;
    std::string Kc;
    BitTable bitTable;
    std::string Content;

public:
    explicit Kelf(KeyStore &_ks)
        : ks(_ks)
        , bitTable()
    {
    }

    int LoadKelf(const std::string &filename);
    int SaveKelf(const std::string &filename, int header);
    int LoadContent(const std::string &filename, int header);
    int SaveContent(const std::string &filename);

    std::string GetHeaderSignature(KELFHeader &header);
    std::string DeriveKeyEncryptionKey(KELFHeader &header);
    void DecryptKeys(const std::string &KEK);
    void EncryptKeys(const std::string &KEK);
    std::string GetBitTableSignature();
    std::string GetRootSignature(const std::string &HeaderSignature, const std::string &BitTableSignature);
    void DecryptContent(int keycount);
    int VerifyContentSignature();
};

#endif
