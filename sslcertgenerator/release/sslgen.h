/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Bertrand Martel
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
/**
    sslgen.h
    @author Bertrand Martel
    @version 1.0
*/
#ifndef SSLGEN_H
#define SSLGEN_H

#include <string>
#include <openssl/x509.h>
#include <pthread.h>

/**
 * @brief
 *  Define structure for certificate entries
 *
 */
typedef struct {
    char *country_name;
    char *state_province_name;
    char *locality_name;
    char *organization_name;
    char *organizational_unit_name;
    char *common_name;
} cert_entries;

/**
 * @brief
 *  Define structure for output certificates
 *
 */
typedef struct {
    char *public_key_pem;
    int public_key_pem_length;
    char *private_key_pem;
    int private_key_pem_length;
    char *key_pkcs12;
    int pkcs12_key_length;
} certificate_raw;

/**
 * @brief
 *  Define structure for issuer certificate
 *
 */
typedef struct{
    char *public_key_pem;
    int public_key_pem_size;
    char *private_key_pem;
    int private_key_pem_size;
    char *pass;
} ca_cert;

class sslgen
{

public:

    sslgen();

    /**
     * @brief SslGen::createKeys
     *      Core functions to generate certificates
     *
     * @param entries
     *       certificate entries
     * @param date_start
     *       validation cert date start
     * @param date_end
     *       validation cert date end
     * @param isSignWithCa
     *       define if cert keys are to be signed with issuer cert defined in cert_item
     * @param cert_item
     *       cert issuer to sign keys with
     * @param serial
     *       cert serial number
     * @param passin
     *       optionnal pass for private key (and PKCS12)
     * @param rsa_key_size
     *       rsa key size
     * @param certs
     *       output certificate structure
     * @return
     *       0 success / -1 error
     */
    int createKeys(cert_entries *entries,struct tm *dateStart,struct tm *dateEnd,bool isSignWithCa,ca_cert *ca_cert_item,int serial,char *passin,int rsa_key_size,certificate_raw *certs);

    /**
     * @brief SslGen::create_standalone_keys
     *      Generate unsigned public/private keys in PEM / PKCS12 format
     *
     * @param entries
     *       certificate entries
     * @param date_start
     *       validation cert date start
     * @param date_end
     *       validation cert date end
     * @param serial
     *       cert serial number
     * @param passin
     *       optionnal pass for private key (and PKCS12)
     * @param rsa_key_size
     *       rsa key size
     * @param certs
     *       output certificate structure
     * @return
     *        0 success / -1 error
     */
    int create_standalone_keys(cert_entries *entries,struct tm *date_start,struct tm *date_end,int serial,char *passin,int rsa_key_size,certificate_raw *certs);

    /**
     * @brief SslGen::create_signed_keys
     *       Generate signed certificates (from CA or cert issuer)
     * @param entries
     *       certificate entries
     * @param date_start
     *       validation cert date start
     * @param date_end
     *       validation cert date end
     * @param serial
     *       cert serial number
     * @param passin
     *       optionnal pass for private key (and PKCS12)
     * @param rsa_key_size
     *       rsa key size
     * @param cert_item
     *       issuer certificate we use to sign keys
     * @param certs
     *       output certificate structure
     * @return
     *        0 success / -1 error
     */
    int create_signed_keys(cert_entries *entries,struct tm *date_start,struct tm *date_end,int serial,char *passin,int rsa_key_size,ca_cert *ca_cert_item,certificate_raw* certs);

    /**
     * @brief add_ext
     *      Add certificate extension
     * @param cert
     * @param issuer
     * @param nid
     * @param value
     * @return
     */
    int add_ext(X509 *cert,X509* issuer, int nid, char *value);

    /**
     * @brief SslGen::create_dh_key
     *      Generate Diffie Hellman key
     * @param key_size
     * @param file_path
     * @return
     */
    pthread_t create_dh_key(int key_size,char* file_path);

    /**
     * @brief SslGen::createCertEntry
     *      Create certificate entry and add to X509_NAME
     * @param subj
     * @param entry_key
     * @param entry_val
     */
    void createCertEntry(X509_NAME *subj,char *entry_key,char *entry_val);

    /**
     * @brief SslGen::fatal_error
     *      Error catch function
     * @param file
     * @param line
     * @param msg
     */
    void fatal_error(const char *file, int line, const char *msg);

    /**
     * @brief SslGen::setOutputP12
     *      enable/disable PKCS12 format output and set output file path
     * @param enable_p12
     *      enable/disable PKCS12 format
     * @param key_file
     *      PKCS12 file path containing public and private key
     */
    void setOutputP12(bool enable_file,char* key_file);

    /**
     * @brief SslGen::setOutputPEM
     *      enable/disable PEM format output and set output file path
     *
     * @param enable_file
     * @param public_key_file
     *      file to store public key
     * @param private_key_file
     *      file to store private key
    */
    void setOutputPEM(bool enable_file,char* public_key_file,char* private_key_file);

private:

    /* define if pem format is enabled*/
    bool is_pem;

    /*define if pkcs12 foramt is enabled*/
    bool is_p12;

    /*set output public key PEM file path*/
    char *public_key_pem_file;

    /*set output private key PEM file path*/
    char *private_key_pem_file;

    /*set output pkcs12 file path*/
    char *key_p12_file;
};

#endif
