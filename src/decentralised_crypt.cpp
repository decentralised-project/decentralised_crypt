#include "decentralised_crypt.h"


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
