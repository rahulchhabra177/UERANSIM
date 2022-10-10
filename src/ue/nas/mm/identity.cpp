// This file is a part of UERANSIM open source project.
// Copyright (c) 2021 ALİ GÜNGÖR.
//
// The software and all associated files are licensed under GPL-3.0
// and subject to the terms and conditions defined in LICENSE file.
//
#include "mm.hpp"

#include <utils/common.hpp>

#include <stdio.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <bits/stdc++.h>
using namespace std;
namespace nr::ue
{

void NasMm::receiveIdentityRequest(const nas::IdentityRequest &msg)
{
    nas::IdentityResponse resp;

    if (msg.identityType.value == nas::EIdentityType::SUCI)
    {
        resp.mobileIdentity = getOrGenerateSuci();
    }
    else if (msg.identityType.value == nas::EIdentityType::IMEI)
    {
        resp.mobileIdentity.type = nas::EIdentityType::IMEI;
        resp.mobileIdentity.value = *m_base->config->imei;
    }
    else if (msg.identityType.value == nas::EIdentityType::IMEISV)
    {
        resp.mobileIdentity.type = nas::EIdentityType::IMEISV;
        resp.mobileIdentity.value = *m_base->config->imeiSv;
    }
    else if (msg.identityType.value == nas::EIdentityType::GUTI)
    {
        resp.mobileIdentity = m_storage->storedGuti->get();
    }
    else if (msg.identityType.value == nas::EIdentityType::TMSI)
    {
        // TMSI is already a part of GUTI
        resp.mobileIdentity = m_storage->storedGuti->get();
        if (resp.mobileIdentity.type != nas::EIdentityType::NO_IDENTITY)
        {
            resp.mobileIdentity.type = nas::EIdentityType::TMSI;
            resp.mobileIdentity.gutiOrTmsi.plmn = {};
            resp.mobileIdentity.gutiOrTmsi.amfRegionId = {};
        }
    }
    else
    {
        resp.mobileIdentity.type = nas::EIdentityType::NO_IDENTITY;
        m_logger->err("Requested identity is not available: %d", (int)msg.identityType.value);
    }

    sendNasMessage(resp);
}

nas::IE5gsMobileIdentity NasMm::getOrGenerateSuci()
{
    if (m_timers->t3519.isRunning() && m_storage->storedSuci->get().type != nas::EIdentityType::NO_IDENTITY)
        return m_storage->storedSuci->get();

    m_storage->storedSuci->set(generateSuci());

    m_timers->t3519.start();

    if (m_storage->storedSuci->get().type == nas::EIdentityType::NO_IDENTITY)
        return {};
    return m_storage->storedSuci->get();
}

/* Convert an EC key's public key to a binary array. */
int ec_key_public_key_to_bin(const EC_KEY  *ec_key,
                             uint8_t      **pubk,     // out (must free)
                             size_t        *pubk_len) // out
{
        const EC_GROUP *ec_group   = EC_KEY_get0_group(ec_key);
        const EC_POINT *pub        = EC_KEY_get0_public_key(ec_key);
        BIGNUM         *pub_bn     = BN_new();
        BN_CTX         *pub_bn_ctx = BN_CTX_new();

        BN_CTX_start(pub_bn_ctx);

        EC_POINT_point2bn(ec_group, pub, POINT_CONVERSION_COMPRESSED,
                          pub_bn, pub_bn_ctx);

        *pubk_len = BN_num_bytes(pub_bn);
        *pubk = (uint8_t*)OPENSSL_malloc(*pubk_len);

        if (BN_bn2bin(pub_bn, *pubk) != *pubk_len)
            return -1;

        BN_CTX_end(pub_bn_ctx);
        BN_CTX_free(pub_bn_ctx);
        BN_clear_free(pub_bn);

        return 0;
}

/* Convert an EC key's private key to a binary array. */
int ec_key_private_key_to_bin(const EC_KEY  *ec_key,
                              uint8_t      **privk,     // out (must free)
                              size_t        *privk_len) // out
{
        const BIGNUM *priv = EC_KEY_get0_private_key(ec_key);

        *privk_len = BN_num_bytes(priv);
        *privk = (uint8_t*)OPENSSL_malloc(*privk_len);

        if (BN_bn2bin(priv, *privk) != *privk_len)
            return -1;

        return 0;
}

/* Convert a public key binary array to an EC point. */
int ec_key_public_key_bin_to_point(const EC_GROUP  *ec_group,
                                   const uint8_t   *pubk,
                                   const size_t     pubk_len,
                                   EC_POINT       **pubk_point) // out
{
        BIGNUM   *pubk_bn;
        BN_CTX   *pubk_bn_ctx;

        *pubk_point = EC_POINT_new(ec_group);

        pubk_bn = BN_bin2bn(pubk, pubk_len, NULL);
        pubk_bn_ctx = BN_CTX_new();
        BN_CTX_start(pubk_bn_ctx);

        EC_POINT_bn2point(ec_group, pubk_bn, *pubk_point, pubk_bn_ctx);

        BN_CTX_end(pubk_bn_ctx);
        BN_CTX_free(pubk_bn_ctx);
        BN_clear_free(pubk_bn);

        return 0;
}

/* (TX) Generate an ephemeral EC key and associated shared symmetric key. */
int ecies_transmitter_generate_symkey(const int       curve,
                                      const uint8_t  *peer_pubk,
                                      const size_t    peer_pubk_len,
                                      uint8_t       **epubk,         // out (must free)
                                      size_t         *epubk_len,     // out
                                      uint8_t       **skey,          // out (must free)
                                      size_t         *skey_len)      // out
{
        EC_KEY         *ec_key          = NULL; /* ephemeral keypair */
        const EC_GROUP *ec_group        = NULL;
        EC_POINT       *peer_pubk_point = NULL;

        /* Create and initialize a new empty key pair on the curve. */
        ec_key = EC_KEY_new_by_curve_name(curve);
        EC_KEY_generate_key(ec_key);
        ec_group = EC_KEY_get0_group(ec_key);

        /* Allocate a buffer to hold the shared symmetric key. */
        *skey_len = ((EC_GROUP_get_degree(ec_group) + 7) / 8);
        *skey     = (uint8_t*)OPENSSL_malloc(*skey_len);

        /* Convert the peer public key to an EC point. */
        ec_key_public_key_bin_to_point(ec_group, peer_pubk, peer_pubk_len,
                                       &peer_pubk_point);

        /* Generate the shared symmetric key (diffie-hellman primitive). */
        *skey_len = ECDH_compute_key(*skey, *skey_len, peer_pubk_point,
                                     ec_key, NULL);

        /* Write the ephemeral key's public key to the output buffer. */
        ec_key_public_key_to_bin(ec_key, epubk, epubk_len);

        /*
         * NOTE: The private key is thrown away here...
         * With ECIES the transmitter EC key pair is a one time use only.
         */

        return 0;
}

/* (RX) Generate the shared symmetric key. */
int ecies_receiver_generate_symkey(const EC_KEY   *ec_key,
                                   const uint8_t  *peer_pubk,
                                   const size_t    peer_pubk_len,
                                   uint8_t       **skey,          // out (must free)
                                   size_t         *skey_len)      // out
{
        const EC_GROUP *ec_group        = EC_KEY_get0_group(ec_key);
        EC_POINT       *peer_pubk_point = NULL;

        /* Allocate a buffer to hold the shared symmetric key. */
        *skey_len = ((EC_GROUP_get_degree(ec_group) + 7) / 8);
        *skey     = (uint8_t*)OPENSSL_malloc(*skey_len);

        /* Convert the peer public key to an EC point. */
        ec_key_public_key_bin_to_point(ec_group, peer_pubk, peer_pubk_len,
                                       &peer_pubk_point);

        /* Generate the shared symmetric key (diffie-hellman primitive). */
        *skey_len = ECDH_compute_key(*skey, *skey_len, peer_pubk_point,
                                     (EC_KEY *)ec_key, NULL);

        return 0;
}

/* Encrypt plaintext data using 256b AES-GCM. */
int aes_gcm_256b_encrypt(uint8_t  *plaintext,
                         size_t    plaintext_len,
                         uint8_t  *skey,
                         uint8_t  *aad,
                         size_t    aad_len,
                         uint8_t **iv,             // out (must free)
                         uint8_t  *iv_len,         // out
                         uint8_t **tag,            // out (must free)
                         uint8_t  *tag_len,        // out
                         uint8_t **ciphertext,     // out (must free)
                         uint8_t  *ciphertext_len) // out
{
        EVP_CIPHER_CTX *ctx;
        int len;

        /* Allocate buffers for the IV, tag, and ciphertext. */
        *iv_len = 12;
        *iv = (uint8_t*)OPENSSL_malloc(*iv_len);
        *tag_len = 8;
        *tag = (uint8_t*)OPENSSL_malloc(*tag_len);
        *ciphertext = (uint8_t*)OPENSSL_malloc((plaintext_len + 0xf) & ~0xf);

        /* Initialize the context and encryption operation. */
        ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);

        /* Generate a new random IV. */
        RAND_pseudo_bytes(*iv, *iv_len);

        /* Prime the key and IV. */
        EVP_EncryptInit_ex(ctx, NULL, NULL, skey, *iv);

        /* Prime with any additional authentication data. */
        if (aad && aad_len)
            EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len);

        /* Encrypt the data. */
        EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len);
        *ciphertext_len = len;

        /* Finalize the encryption session. */
        EVP_EncryptFinal_ex(ctx, (*ciphertext + len), &len);
        *ciphertext_len += len;

        /* Get the authentication tag. */
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, *tag_len, *tag);

        EVP_CIPHER_CTX_free(ctx);

        return 0;
}

/* Decrypt ciphertext data using 256b AES-GCM. */
int aes_gcm_256b_decrypt(uint8_t  *ciphertext,
                         size_t    ciphertext_len,
                         uint8_t  *skey,
                         uint8_t  *aad,
                         size_t    aad_len,
                         uint8_t  *iv,
                         uint8_t   iv_len,
                         uint8_t  *tag,
                         size_t    tag_len,
                         uint8_t **plaintext,     // out (must free)
                         uint8_t  *plaintext_len) // out
{
        EVP_CIPHER_CTX *ctx;
        int len, rc;

        /* Allocate a buffer for the plaintext. */
        *plaintext = (uint8_t*)OPENSSL_malloc(ciphertext_len);

        /* Initialize the context and encryption operation. */
        ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);

        /* Prime the key and IV (+length). */
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL);
        EVP_DecryptInit_ex(ctx, NULL, NULL, skey, iv);

        /* Prime with any additional authentication data. */
        if (aad && aad_len)
                EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len);

        /* Decrypt the data. */
        EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len);
        *plaintext_len = len;

        /* Set the expected tag value. */
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, tag);

        /* Finalize the decryption session. Returns 0 with a bad tag! */
        rc = EVP_DecryptFinal_ex(ctx, (*plaintext + len), &len);

        EVP_CIPHER_CTX_free(ctx);

        if (rc > 0)
        {
                *plaintext_len += len;
                return 0;
        }

}

int ecies_receiver_load_key(char     *filename,
                            EC_KEY  **ec_key,    // out
                            int      *curve,     // out
                            uint8_t **pubk,      // out (must free)
                            size_t   *pubk_len,  // out
                            uint8_t **privk,     // out (must free)
                            size_t   *privk_len) // out
{
        const EC_GROUP *ec_group = NULL;
        BIO            *bio_key  = NULL;
        BIO            *bio_out  = NULL; /* stdout */

        /*
         * Create a BIO object wrapping a file pointer to read the EC key file
         * in DER format. Then read in and parse the EC key from the file.
         */
        bio_key = BIO_new_file(filename, "r");
        if (bio_key == NULL)
                return -1;
        *ec_key = d2i_ECPrivateKey_bio(bio_key, NULL);
        if (*ec_key == NULL)
                return 2;
        BIO_free(bio_key);
        /* Get the curve parameters from the EC key. */
        ec_group = EC_KEY_get0_group(*ec_key);

        /* Create a BIO object wrapping stdout. */
        bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

        /* Set the point conversion outputs to always be 'uncompressed'. */
        EC_KEY_set_conv_form(*ec_key, POINT_CONVERSION_COMPRESSED);

        /* Get the EC key's public key in a binary array format. */
        ec_key_public_key_to_bin(*ec_key, pubk, pubk_len);

        /* Get the EC key's private key in a binary array format. */
        ec_key_private_key_to_bin(*ec_key, privk, privk_len);

        /* Get the EC key's curve name. */
        *curve = EC_GROUP_get_curve_name(ec_group);

        return 0;
}

int ecies_transmitter_send_message(uint8_t        *msg,
                                   size_t          msg_len,
                                   int             curve,
                                   const uint8_t  *peer_pubk,
                                   const uint8_t   peer_pubk_len,
                                   uint8_t       **epubk,          // out (must free)
                                   size_t         *epubk_len,      // out
                                   uint8_t       **iv,             // out (must free)
                                   uint8_t        *iv_len,         // out
                                   uint8_t       **tag,            // out (must free)
                                   uint8_t        *tag_len,        // out
                                   uint8_t       **ciphertext,     // out (must free)
                                   uint8_t        *ciphertext_len) // out
{
        uint8_t *skey      = NULL; // DH generated shared symmetric key
        size_t   skey_len  = 0;

        /* Generate the shared symmetric key (transmitter). */
        ecies_transmitter_generate_symkey(curve, peer_pubk, peer_pubk_len,
                                          epubk, epubk_len, &skey, &skey_len);
        if (skey_len != 32)
            return skey_len;

        /* Encrypt the data using 256b AES-GCM. */
        aes_gcm_256b_encrypt(msg, msg_len, skey, NULL, 0,
                             iv, iv_len, tag, tag_len,
                             ciphertext, ciphertext_len);

        free(skey);

        return 0;
}

int ecies_receiver_recv_message(const EC_KEY  *ec_key,
                                const uint8_t *peer_pubk,
                                const uint8_t  peer_pubk_len,
                                uint8_t       *iv,
                                uint32_t       iv_len,
                                uint8_t       *tag,
                                uint32_t       tag_len,
                                uint8_t       *ciphertext,
                                uint32_t       ciphertext_len)
{
        // Shared symmetric encryption key (DH generated)
        uint8_t *skey     = NULL;
        size_t   skey_len = 0;

        // Decrypted data (plaintext)
        uint8_t *plaintext     = NULL;
        uint8_t  plaintext_len = 0;

        /* Generate the shared symmetric key (receiver). */
        ecies_receiver_generate_symkey(ec_key, peer_pubk, peer_pubk_len,
                                       &skey, &skey_len);
        if (skey_len != 32)
            return skey_len;

        /* Decrypt the data using 256b AES-GCM. */
        aes_gcm_256b_decrypt(ciphertext, ciphertext_len, skey, NULL, 0,
                             iv, iv_len, tag, tag_len,
                             &plaintext, &plaintext_len);

        free(skey);
        free(plaintext);

        return 0;
}



std::string encrypt(int protectionSchemaId, int homeNetworkPublicKeyIdentifier, std::string schemeOutput){
        EC_KEY *ec_key = NULL; // EC key from key file

        // Receiver's EC Key (public, private, curve)
        uint8_t *pubk      = NULL;
        size_t   pubk_len  = 0;
        uint8_t *privk     = NULL;
        size_t   privk_len = 0;
        int      curve;

        // Transmitter's ephemeral public EC Key
        uint8_t *epubk     = NULL;
        size_t   epubk_len = 0;

        // AES-GCM encrypted data (IV, authentication tag, ciphertext)
        uint8_t *iv             = NULL;
        uint8_t  iv_len         = 0;
        uint8_t *tag            = NULL;
        uint8_t  tag_len        = 0;
        uint8_t *ciphertext     = NULL;
        uint8_t  ciphertext_len = 0;

        /* ECIES Receiver loads the EC key. */
        ecies_receiver_load_key("/home/baadalvm/Testing/ecies/keyout.der", &ec_key, &curve,
                                &pubk, &pubk_len, &privk, &privk_len);
        
        ecies_transmitter_send_message((uint8_t*) reinterpret_cast<const uint8_t*>(schemeOutput.c_str()), (schemeOutput.length()),
                                       curve, pubk, pubk_len,
                                       &epubk, &epubk_len,
                                       &iv, &iv_len, &tag, &tag_len,
                                       &ciphertext, &ciphertext_len);

        string output;
        for(int i=0;i<epubk_len;i++)
        {
            uint8_t c = epubk[i];
            output.push_back((c/16>9)?c/16 - 10 + 'a' : c/16 - 0 + '0');
            output.push_back((c%16>9)?c%16 - 10 + 'a' : c%16 - 0 + '0');
        }
        for(int i=0;i<ciphertext_len;i++)
        {
            uint8_t c = ciphertext[i];
            output.push_back((c/16>9)?c/16 - 10 + 'a' : c/16 - 0 + '0');
            output.push_back((c%16>9)?c%16 - 10 + 'a' : c%16 - 0 + '0');
        }
        for(int i=0;i<iv_len;i++)
        {
            uint8_t c = iv[i];
            output.push_back((c/16>9)?c/16 - 10 + 'a' : c/16 - 0 + '0');
            output.push_back((c%16>9)?c%16 - 10 + 'a' : c%16 - 0 + '0');
        }
        for(int i=0;i<tag_len;i++)
        {
            uint8_t c = tag[i];
            output.push_back((c/16>9)?c/16 - 10 + 'a' : c/16 - 0 + '0');
            output.push_back((c%16>9)?c%16 - 10 + 'a' : c%16 - 0 + '0');
        }
        return output;

}

nas::IE5gsMobileIdentity NasMm::generateSuci()
{
    auto &supi = m_base->config->supi;
    auto &plmn = m_base->config->hplmn;

    if (!supi.has_value())
        return {};
        // m_logger->err("BEYOND 5G 1212 F");

    if (supi->type != "imsi")
    {
        m_logger->err("SUCI generating failed, invalid SUPI type: %s", supi->value.c_str());
        return {};
    }
        // m_logger->err("BEYOND 5G 1212 G");

    const std::string &imsi = supi->value;

    nas::IE5gsMobileIdentity ret;
    ret.type = nas::EIdentityType::SUCI;
    ret.supiFormat = nas::ESupiFormat::IMSI;
    // ret.supiFormat = nas::ESupiFormat::NETWORK_SPECIFIC_IDENTIFIER;
    ret.imsi.plmn.isLongMnc = plmn.isLongMnc;
    ret.imsi.plmn.mcc = plmn.mcc;
    ret.imsi.plmn.mnc = plmn.mnc;
    ret.imsi.routingIndicator = "0000";
    ret.imsi.protectionSchemaId = 1;
    ret.imsi.homeNetworkPublicKeyIdentifier = 255;
    ret.imsi.schemeOutput = imsi.substr(plmn.isLongMnc ? 6 : 5);
        // m_logger->err("BEYOND 5G 1212 %s",imsi.c_str() );
        // m_logger->err("BEYOND 5G 1212 %02x",ret.type );
        // m_logger->err("BEYOND 5G 1212 %d",ret.supiFormat );
        // m_logger->err("BEYOND 5G 1212 %d",(ret.imsi.plmn.isLongMnc) );
        // m_logger->err("BEYOND 5G 1212 %d",(ret.imsi.plmn.mcc) );
        // m_logger->err("BEYOND 5G 1212 %d",(ret.imsi.plmn.mnc) );
        // m_logger->err("BEYOND 5G 1212 %s",ret.imsi.routingIndicator.c_str() );
        // m_logger->err("BEYOND 5G 1212 %d",(ret.imsi.protectionSchemaId) );
        // m_logger->err("BEYOND 5G 1212 %d",(ret.imsi.homeNetworkPublicKeyIdentifier) );
        // m_logger->err("BEYOND 5G 1212 %s",ret.imsi.schemeOutput.c_str() );
        // m_logger->err("BEYOND 5G 1212 H");
        // m_logger->err("BEYOND 5G 1212 %s",supi->value.c_str() );

    ret.imsi.schemeOutput = encrypt(ret.imsi.protectionSchemaId, ret.imsi.homeNetworkPublicKeyIdentifier, ret.imsi.schemeOutput);
        // m_logger->err("BEYOND 5G encr %s",ret.imsi.schemeOutput.c_str() );
        // m_logger->err("BEYOND 5G len %d",ret.imsi.schemeOutput.length() );
        
    return ret;
}

nas::IE5gsMobileIdentity NasMm::getOrGeneratePreferredId()
{
    if (m_storage->storedGuti->get().type != nas::EIdentityType::NO_IDENTITY)
        return m_storage->storedGuti->get();

    auto suci = getOrGenerateSuci();
    // m_logger->err("BEYOND 5G 1212 A");
    // m_logger->err("BEYOND 5G 1212 %02X",suci );
    // m_logger->err("BEYOND 5G 1212 %s",suci );
    if (suci.type != nas::EIdentityType::NO_IDENTITY)
    {
    // m_logger->err("BEYOND 5G 1212 I");
        return suci;
    }
    else if (m_base->config->imei.has_value())
    {
        nas::IE5gsMobileIdentity res{};
        res.type = nas::EIdentityType::IMEI;
        res.value = *m_base->config->imei;
        return res;
    }
    else if (m_base->config->imeiSv.has_value())
    {
        nas::IE5gsMobileIdentity res{};
        res.type = nas::EIdentityType::IMEISV;
        res.value = *m_base->config->imeiSv;
        return res;
    }
    else
    {
        nas::IE5gsMobileIdentity res{};
        res.type = nas::EIdentityType::NO_IDENTITY;
        return res;
    }
}

} // namespace nr::ue
