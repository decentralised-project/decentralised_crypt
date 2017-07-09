#ifndef DECENTRALISED_CRYPT_H
#define DECENTRALISED_CRYPT_H

#include <QObject>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/ecdsa.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

class decentralised_crypt: public QObject
{
    Q_OBJECT
public:
    explicit decentralised_crypt(QObject *parent = 0);
    virtual ~decentralised_crypt() {
        if (_eckey)
            EC_KEY_free(_eckey);

        if (_publicKey)
            EC_POINT_free(_publicKey);

        EVP_cleanup();
    }

    EC_KEY* generate_key_pair();
    const EC_POINT* get_public_key(EC_KEY *keypair);
    QByteArray ecdh(EC_KEY *key, const EC_POINT *pPub);
    QString to_base58(const EC_POINT* public_key);
    const EC_POINT* from_base58(QString base58);

signals:

private:
    EC_KEY* _eckey;
    EC_POINT* _publicKey;
};

#endif // DECENTRALISED_CRYPT_H
