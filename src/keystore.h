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
#ifndef __KEYSTORE_H__
#define __KEYSTORE_H__

#include <string>

#define KEYSTORE_ERROR_OPEN_FAILED        -1
#define KEYSTORE_ERROR_LINE_NOT_KEY_VALUE -2
#define KEYSTORE_ERROR_ODD_LEN_VALUE      -3
#define KEYSTORE_ERROR_MISSING_KEY        -4

class KeyStore
{
    std::string SignatureMasterKey;
    std::string SignatureHashKey;
    std::string KbitMasterKey;
    std::string KbitIV;
    std::string KcMasterKey;
    std::string KcIV;
    std::string RootSignatureMasterKey;
    std::string RootSignatureHashKey;
    std::string ContentTableIV;
    std::string ContentIV;
    std::string ArcadeKbit;
    std::string ArcadeKc;

public:
    int Load(std::string filename, std::string KeyStoreEntry);

    std::string GetSignatureMasterKey() { return SignatureMasterKey; }
    std::string GetSignatureHashKey() { return SignatureHashKey; }
    std::string GetKbitMasterKey() { return KbitMasterKey; }
    std::string GetKbitIV() { return KbitIV; }
    std::string GetKcMasterKey() { return KcMasterKey; }
    std::string GetKcIV() { return KcIV; }
    std::string GetRootSignatureMasterKey() { return RootSignatureMasterKey; }
    std::string GetRootSignatureHashKey() { return RootSignatureHashKey; }
    std::string GetContentTableIV() { return ContentTableIV; }
    std::string GetContentIV() { return ContentIV; }
    std::string GetArcadeKbit() { return ArcadeKbit; }
    std::string GetArcadeKc() { return ArcadeKc; }

    static std::string getErrorString(int err);
};

#endif
