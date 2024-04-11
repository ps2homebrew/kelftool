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
#include "keystore.h"
#include "inipp.h"
#include <fstream>
#include <vector>
#include <sstream>
#include <iostream>

std::vector<std::string> split(const std::string &s, char delimiter)
{
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);
    while (std::getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

int char2int(char input)
{
    if (input >= '0' && input <= '9')
        return input - '0';
    if (input >= 'A' && input <= 'F')
        return input - 'A' + 10;
    if (input >= 'a' && input <= 'f')
        return input - 'a' + 10;
    throw std::invalid_argument("Invalid input string");
}

std::string hex2bin(const std::string &src)
{
    std::string hex;
    for (unsigned long i = 0; i < src.size(); i += 2) {
        char chr = char2int(src[i]) << 4 | char2int(src[i + 1]);
        hex += chr;
    }
    return hex;
}

int KeyStore::Load(std::string filename, std::string KeySet = "default")
{
    inipp::Ini<char> ini;
    std::ifstream infile(filename);
    if (infile.fail())
        return KEYSTORE_ERROR_OPEN_FAILED;
	ini.parse(infile);
	ini.strip_trailing_comments();
	ini.default_section(ini.sections["default"]);
	ini.interpolate();
    if (ini.sections.find(KeySet) == ini.sections.end()) {
        return KEYSTORE_SECTION_MISSING;
    }
    inipp::get_value(ini.sections[KeySet], "MG_SIG_MASTER_KEY", SignatureMasterKey);
    inipp::get_value(ini.sections[KeySet], "MG_SIG_HASH_KEY", SignatureHashKey);
    inipp::get_value(ini.sections[KeySet], "MG_KBIT_MASTER_KEY", KbitMasterKey);
    inipp::get_value(ini.sections[KeySet], "MG_KBIT_IV", KbitIV);
    inipp::get_value(ini.sections[KeySet], "MG_KC_MASTER_KEY", KcMasterKey);
    inipp::get_value(ini.sections[KeySet], "MG_KC_IV", KcIV);
    inipp::get_value(ini.sections[KeySet], "MG_ROOTSIG_MASTER_KEY", RootSignatureMasterKey);
    inipp::get_value(ini.sections[KeySet], "MG_ROOTSIG_HASH_KEY", RootSignatureHashKey);
    inipp::get_value(ini.sections[KeySet], "MG_CONTENT_TABLE_IV", ContentTableIV);
    inipp::get_value(ini.sections[KeySet], "MG_CONTENT_IV", ContentIV);
    inipp::get_value(ini.sections[KeySet], "OVERRIDE_KBIT", OverrideKbit);
    inipp::get_value(ini.sections[KeySet], "OVERRIDE_KC", OverrideKc);
    SignatureMasterKey = hex2bin(SignatureMasterKey);
    SignatureHashKey = hex2bin(SignatureHashKey);
    KbitMasterKey = hex2bin(KbitMasterKey);
    KbitIV = hex2bin(KbitIV);
    KcMasterKey = hex2bin(KcMasterKey);
    KcIV = hex2bin(KcIV);
    RootSignatureMasterKey = hex2bin(RootSignatureMasterKey);
    RootSignatureHashKey = hex2bin(RootSignatureHashKey);
    ContentTableIV = hex2bin(ContentTableIV);
    ContentIV = hex2bin(ContentIV);
    OverrideKbit = hex2bin(OverrideKbit);
    OverrideKc = hex2bin(OverrideKc);

    if (SignatureMasterKey.size() == 0 || SignatureHashKey.size() == 0 ||
        KbitMasterKey.size() == 0 || KbitIV.size() == 0 ||
        KcMasterKey.size() == 0 || KcIV.size() == 0 ||
        RootSignatureMasterKey.size() == 0 || RootSignatureHashKey.size() == 0 ||
        ContentTableIV.size() == 0 || ContentIV.size() == 0)
        return KEYSTORE_ERROR_MISSING_KEY;

    return 0;
}

std::string KeyStore::getErrorString(int err)
{
    switch (err) {
        case 0:
            return "Success";
        case KEYSTORE_ERROR_OPEN_FAILED:
            return "Failed to open keystore!";
        case KEYSTORE_ERROR_LINE_NOT_KEY_VALUE:
            return "Line in the keystore file is not key=value pair!";
        case KEYSTORE_ERROR_ODD_LEN_VALUE:
            return "Odd length hex value in keystore!";
        case KEYSTORE_ERROR_MISSING_KEY:
            return "Some keys are missing from the keystore!";
        case KEYSTORE_SECTION_MISSING:
            return "Cant find requested section in keystore!";
        default:
            return "Unknown error";
    }
}
