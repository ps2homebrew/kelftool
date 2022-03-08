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

static uint8_t USER_HEADER_FMCB[16] = {0x01, 0x00, 0x00, 0x01, 0x00, 0x03, 0x00, 0x4A, 0x00, 0x01, 0x02, 0x19, 0x00, 0x00, 0x00, 0x56};
static uint8_t USER_HEADER_FHDB[16] = {0x01, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00, 0x4A, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x1B};
static uint8_t USER_HEADER_MBR[16]  = {0x01, 0x00, 0x00, 0x04, 0x00, 0x02, 0x01, 0x57, 0x07, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2A};

// static uint8_t USER_Kc_MBR[16]  = {0xD2 ,0xC6 ,0x8F ,0xC2 ,0xEB ,0xA0 ,0x5B ,0x63 ,0x3F ,0x0B ,0xF8 ,0x7B ,0x46 ,0x0E ,0x0D ,0x93};
// static uint8_t USER_Kbit_MBR[16]  = {0x83 ,0x1E ,0x4E ,0x4B ,0x42 ,0xCA ,0x7F ,0x39 ,0x0C ,0xB7 ,0xC5 ,0xFB ,0x81 ,0xB1 ,0x10 ,0xDA};
static uint8_t USER_Kbit_MBR[16]  = {0x82, 0xf0, 0x29, 0xad, 0xe9, 0x53, 0x23, 0xf5, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa};
static uint8_t USER_Kbit_FHDB[16] = {0x40, 0xe9, 0x80, 0x4d, 0x2e, 0x92, 0xb0, 0xa8, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa};
static uint8_t USER_Kbit_FMCB[16] = {0xd9, 0x4a, 0x2e, 0x56, 0x01, 0x6e, 0xa7, 0x31, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa};

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
#define HDR_FLAG4_3DES      0x20   // Set in kelf. HDR_FLAG4_1DES should be unset. Represents Single DES encryption
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

// MGZones region flags. If unset - blocked in that region
#define REGION_JP   0x1  // Japan
#define REGION_NA   0x2  // North America
#define REGION_EU   0x4  // Europe
#define REGION_AU   0x8  // Australia
#define REGION_ASIA 0x10 // Asia
#define REGION_RU   0x20 // Russia
#define REGION_CH   0x40 // China
#define REGION_MX   0x80 // Mexico

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
    {
    }

    int LoadKelf(std::string filename);
    int SaveKelf(std::string filename, int header);
    int LoadContent(std::string filename, int header);
    int SaveContent(std::string filename);

    std::string GetHeaderSignature(KELFHeader &header);
    std::string DeriveKeyEncryptionKey(KELFHeader &header);
    void DecryptKeys(std::string KEK);
    void EncryptKeys(std::string KEK);
    std::string GetBitTableSignature();
    std::string GetRootSignature(std::string HeaderSignature, std::string BitTableSignature);
    void DecryptContent(int keycount);
    int VerifyContentSignature();
};

#endif
