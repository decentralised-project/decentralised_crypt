#include "decentralised_crypt.h"

static const char* pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

decentralised_crypt::decentralised_crypt(QObject *parent) : QObject(parent)
{
    _eckey = NULL;
}

decentralised_crypt::~decentralised_crypt()
{
    if (_eckey)
        EC_KEY_free(_eckey);

    EVP_cleanup();
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
