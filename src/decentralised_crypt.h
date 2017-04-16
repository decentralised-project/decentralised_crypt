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
    ~decentralised_crypt();

    EC_KEY* generate_key_pair();
    const EC_POINT* get_public_key(EC_KEY *keypair);
    QString to_base58(const EC_POINT* public_key);

signals:

private:
    EC_KEY* _eckey;
};

#endif // DECENTRALISED_CRYPT_H
