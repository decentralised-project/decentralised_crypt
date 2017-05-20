#include "decentralised_crypt.h"

static const char* pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

decentralised_crypt::decentralised_crypt(QObject *parent) : QObject(parent)
{
    _eckey = NULL;
    _publicKey = NULL;
}

EC_KEY* decentralised_crypt::generate_key_pair()
{
    if (_eckey)
        EC_KEY_free(_eckey);

    _eckey = EC_KEY_new();

    EC_GROUP *ecgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
    EC_KEY_set_group(_eckey, ecgroup);

    EC_KEY_generate_key(_eckey);

    EC_GROUP_free(ecgroup);

    return _eckey;
}

const EC_POINT* decentralised_crypt::get_public_key(EC_KEY *keypair)
{
    return EC_KEY_get0_public_key(keypair);
}

QString decentralised_crypt::to_base58(const EC_POINT* public_key)
{
    unsigned char *ret = new unsigned char[2048];
    EC_GROUP *ecgrp = EC_GROUP_new_by_curve_name(NID_secp256k1);

    size_t len = EC_POINT_point2oct(ecgrp, public_key, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    EC_POINT_point2oct(ecgrp, public_key, POINT_CONVERSION_UNCOMPRESSED, ret, len, NULL);

    unsigned char* pbegin = ret;
    unsigned char* pend = ret + len;

    // Skip & count leading zeroes.
    int zeroes = 0;
    int length = 0;
    while (pbegin != pend && *pbegin == 0) {
        pbegin++;
        zeroes++;
    }
    // Allocate enough space in big-endian base58 representation.
    int size = (pend - pbegin) * 138 / 100 + 1; // log(256) / log(58), rounded up.
    std::vector<unsigned char> b58(size);
    // Process the bytes.
    while (pbegin != pend) {
        int carry = *pbegin;
        int i = 0;
        // Apply "b58 = b58 * 256 + ch".
        for (std::vector<unsigned char>::reverse_iterator it = b58.rbegin(); (carry != 0 || i < length) && (it != b58.rend()); it++, i++) {
            carry += 256 * (*it);
            *it = carry % 58;
            carry /= 58;
        }

        //assert(carry == 0);
        length = i;
        pbegin++;
    }
    // Skip leading zeroes in base58 result.
    std::vector<unsigned char>::iterator it = b58.begin() + (size - length);
    while (it != b58.end() && *it == 0)
        it++;

    // Translate the result into a string.
    QString str;
    //std::string str;
    str.reserve(zeroes + (b58.end() - it));
    QChar fill = '1';
    str.setRawData(&fill, zeroes);
    while (it != b58.end())
        str += pszBase58[*(it++)];

    free(ret);
    EC_GROUP_free(ecgrp);

    return str;
}

const EC_POINT* decentralised_crypt::from_base58(std::string base58)
{
    const char* psz = base58.c_str();
    std::vector<unsigned char> vch;

    // Skip leading spaces.
    while (*psz && isspace(*psz))
        psz++;
    // Skip and count leading '1's.
    int zeroes = 0;
    while (*psz == '1') {
        zeroes++;
        psz++;
    }
    // Allocate enough space in big-endian base256 representation.
    std::vector<unsigned char> b256(strlen(psz) * 733 / 1000 + 1); // log(58) / log(256), rounded up.
    // Process the characters.
    while (*psz && !isspace(*psz)) {
        // Decode base58 character
        const char* ch = strchr(pszBase58, *psz);
        if (ch == NULL)
            return NULL;

        // Apply "b256 = b256 * 58 + ch".
        int carry = ch - pszBase58;
        for (std::vector<unsigned char>::reverse_iterator it = b256.rbegin(); it != b256.rend(); it++) {
            carry += 58 * (*it);
            *it = carry % 256;
            carry /= 256;
        }
        psz++;
    }
    // Skip trailing spaces.
    while (isspace(*psz))
        psz++;
    if (*psz != 0)
        return NULL;

    // Skip leading zeroes in b256.
    std::vector<unsigned char>::iterator it = b256.begin();
    while (it != b256.end() && *it == 0)
        it++;
    // Copy result into output vector.
    vch.reserve(zeroes + (b256.end() - it));
    vch.assign(zeroes, 0x00);
    while (it != b256.end())
        vch.push_back(*(it++));

    EC_GROUP *ecgrp = EC_GROUP_new_by_curve_name(NID_secp256k1);
    _publicKey = EC_POINT_new(ecgrp);

    EC_POINT_oct2point(ecgrp, _publicKey, vch.data(), vch.size(), NULL);

    EC_GROUP_free(ecgrp);

    return _publicKey;
}

QByteArray decentralised_crypt::ecdh(EC_KEY *key, const EC_POINT *pPub)
{
    int secretLen;
    unsigned char* secret;

    secretLen = EC_GROUP_get_degree(EC_KEY_get0_group(key));
    secretLen = (secretLen + 7) / 8;

    secret = (unsigned char*)malloc(secretLen);
    if (!secret)
    {
        fflush(stderr);
        free(secret);
        throw std::runtime_error("Failed to allocate memory for secret.\n");
    }
    secretLen = ECDH_compute_key(secret, secretLen, pPub, key, NULL);

    QByteArray result;
    // TODO: (needs to be a copy) result.fromRawData(secret, secretLen);
    free(secret);

    return result;
}
