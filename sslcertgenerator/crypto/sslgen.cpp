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
    sslgen.cpp
    @author Bertrand Martel
    @version 1.0
*/
#include "sslgen.h"
#include <stdio.h>
#include <vector>

#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/engine.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/dh.h>

#include <iostream>
#include <fstream>
#include <openssl/stack.h>

#include <openssl/pkcs12.h>
#include <pthread.h>
#include <time.h>

using namespace std;

#define fatal(msg) fatal_error(__FILE__, __LINE__, msg)

int dh_key_size = 1024;

sslgen::sslgen()
{
    is_pem=true;
    is_p12=false;
    public_key_pem_file="";
    private_key_pem_file="";
    key_p12_file="";
}

/**
 * @brief SslGen::setOutputPEM
 *      enable/disable PEM format output and set output file path
 *
 * @param enable_pem
 *       enable/disable PEM format
 * @param public_key_file
 *      file to store public key
 * @param private_key_file
 *      file to store private key
 */
void sslgen::setOutputPEM(bool enable_pem,char* public_key_file,char* private_key_file)
{
    is_pem=enable_pem;
    this->public_key_pem_file=public_key_file;
    this->private_key_pem_file=private_key_file;
}

/**
 * @brief SslGen::setOutputP12
 *      enable/disable PKCS12 format output and set output file path
 * @param enable_p12
 *       enable/disable PKCS12 format
 * @param key_file
 *       PKCS12 file path containing public and private key
 */
void sslgen::setOutputP12(bool enable_p12,char* key_file)
{
    is_p12=enable_p12;
    this->key_p12_file=key_file;
}

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
 *       0 success / -1 error
 */
int sslgen::create_standalone_keys(cert_entries *entries,struct tm *date_start,struct tm *date_end,int serial,char *passin,int rsa_key_size,certificate_raw *certs)
{
    return createKeys(entries, date_start,date_end,false,0,serial,passin,rsa_key_size,certs);
}

/**
 * @brief SslGen::create_signed_keys
 *       Generate signed certificates (from CA or cert issuer)
 * @param entries
 *      certificate entries
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
int sslgen::create_signed_keys(cert_entries *entries,struct tm *date_start,struct tm *date_end,int serial,char *passin,int rsa_key_size,ca_cert *cert_item,certificate_raw *certs)
{
    return createKeys(entries, date_start,date_end,true,cert_item,serial,passin,rsa_key_size,certs);
}

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
int sslgen::createKeys(cert_entries *entries, struct tm *dateStart,struct tm *dateEnd,bool isSignWithCa,ca_cert *cert_item,int serial,char *passin,int rsa_key_size,certificate_raw *certs)
{
    time_t systime, caltime_start,caltime_end; /* time_t is a long */

    long timediff_start,timediff_end;

    time(&systime); /* get the system time in seconds since EPOCH */
    localtime(&systime); /* and return a pointer to the time structure */

    /* get time in seconds from the time structure */
    caltime_start = mktime(dateStart);

    caltime_end = mktime(dateEnd);

    /* don't care if time difference is negative */
    timediff_start=caltime_start-systime;
    if(timediff_start < 0) {
       timediff_start = timediff_start * (-1);
    }
    else{
        timediff_start=0;
    }

    timediff_end=caltime_end-systime;
    if(timediff_end < 0)
       timediff_end = 0;

    RSA *rsakey=0;
    X509 *req=0;
    X509_NAME *subj=0;
    EVP_PKEY *pkey=0;
    EVP_MD *digest=0;

    if (serial==-1){
        cout << "Error happened due to sequence number generation" << endl;
        return -1;
    }

    // openssl setup
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    //seed PRNG
    RAND_load_file("/dev/urandom", 128);

    // Generate the RSA key
    rsakey = RSA_generate_key(rsa_key_size, RSA_F4, NULL, NULL);

    // Create evp obj to hold our rsakey
    if (!(pkey = EVP_PKEY_new()))
        fatal("Could not create EVP object");

    if (!(EVP_PKEY_set1_RSA(pkey, rsakey)))
        fatal("Could not assign RSA key to EVP object");

    // create request object
    if (!(req = X509_new()))
        fatal("Failed to create X509_REQ object");

    X509_set_version(req, NID_X509);

    X509_set_pubkey(req, pkey);

    subj=X509_get_subject_name(req);

    ASN1_INTEGER_set(X509_get_serialNumber(req),serial);

    if (!X509_gmtime_adj(X509_get_notBefore(req), (long)timediff_start))
        fatal("Error setting start date");

    if (!X509_gmtime_adj(X509_get_notAfter(req), (long)timediff_end))
        fatal("Error setting end date");

    if (X509_set_subject_name(req, subj) != 1)
        fatal("Error adding subject to request");

    if (!isSignWithCa){

        createCertEntry(subj,"countryName",entries->country_name);
        createCertEntry(subj,"stateOrProvinceName",entries->state_province_name);
        createCertEntry(subj,"localityName",entries->locality_name);
        createCertEntry(subj,"organizationName",entries->organization_name);
        createCertEntry(subj,"organizationalUnitName",entries->organizational_unit_name);
        createCertEntry(subj,"commonName",entries->common_name);

        X509_set_issuer_name(req,subj);

        digest = (EVP_MD *)EVP_sha1();

        if (!(X509_sign(req, pkey, digest)))
            fatal("Error signing request");

    }
    else{

        cout << "signing certs with CA cert" << endl;

        if (cert_item->private_key_pem!=0 && strcmp(cert_item->private_key_pem,"")!=0){

            if (cert_item->private_key_pem_size>0){

                createCertEntry(subj,"countryName",entries->country_name);
                createCertEntry(subj,"stateOrProvinceName",entries->state_province_name);
                createCertEntry(subj,"localityName",entries->locality_name);
                createCertEntry(subj,"organizationName",entries->organization_name);
                createCertEntry(subj,"organizationalUnitName",entries->organizational_unit_name);
                createCertEntry(subj,"commonName",entries->common_name);

                BIO *bioCa = BIO_new(BIO_s_mem());
                BIO_write(bioCa,cert_item->public_key_pem,cert_item->public_key_pem_size);
                X509 *x509Ca=X509_new();
                PEM_read_bio_X509(bioCa,&x509Ca,0,0);

                X509_set_issuer_name(req,X509_get_subject_name(x509Ca));

                 EVP_PKEY* prv_key = NULL;

                 BIO *bio = BIO_new(BIO_s_mem());

                 BIO_write(bio,cert_item->private_key_pem,cert_item->private_key_pem_size);

                 if (strcmp(cert_item->pass,"")!=0){
                    prv_key = PEM_read_bio_PrivateKey(bio, &prv_key, NULL, cert_item->pass);
                 }
                 else{
                     prv_key = PEM_read_bio_PrivateKey(bio, &prv_key, NULL, NULL);
                 }

                 digest = (EVP_MD *)EVP_sha1();

                 if (!(X509_sign(req, prv_key, digest)))
                     fatal("Error signing request");
            }
            else{
                cout << "CA was not found in database" << endl;
                return -1;
            }
        }
        else{
            cout << "An error has occured! " << endl;
            return -1;
        }
    }

    /*
     * PEM PUBLIC KEY
     */
    if (is_pem)
    {
        BIO *b64Cert = BIO_new (BIO_s_mem());
        PEM_write_bio_X509(b64Cert, req);
        BUF_MEM *bptrCert;
        BIO_get_mem_ptr(b64Cert, &bptrCert);
        int length = bptrCert->length;
        char* public_key = new char[length];
        BIO_read(b64Cert,public_key,length);
        certs->public_key_pem=public_key;
        certs->public_key_pem_length=length;
        public_key[length-1]='\0';
        std::string public_key_str(public_key);
        delete(public_key);
        char *cstr = new char[public_key_str.length() + 1];
        strcpy(cstr, public_key_str.c_str());
        delete(b64Cert);
        delete(bptrCert);
    }
    /*
     * PEM PRIVATE KEY AES 256 ENCODED
     */
    if (is_pem)
    {
        BIO *b64Key = BIO_new (BIO_s_mem());

        if (strcmp(passin,"")==0){

            PEM_write_bio_PrivateKey(b64Key, pkey,NULL, NULL, 0, 0, NULL);
        }
        else{
            PEM_write_bio_PrivateKey(b64Key, pkey,EVP_aes_256_cbc(), NULL, 0, 0, passin);
        }
        
        BUF_MEM *bptrKey;
        BIO_get_mem_ptr(b64Key, &bptrKey);
        int length2 = bptrKey->length;
        char* private_key = new char[length2];
        BIO_read(b64Key,private_key,length2);
        certs->private_key_pem=private_key;
        certs->private_key_pem_length=length2;
        private_key[length2-1]='\0';
        std::string private_key_str(private_key);
        delete(private_key);
        char *cstr = new char[private_key_str.length() + 1];
        strcpy(cstr, private_key_str.c_str());
        delete(b64Key);
        delete(bptrKey);
    }

    /*
     * PKCS12
     */
    PKCS12 *p12;

    p12 = PKCS12_create(passin, entries->common_name, pkey, req, NULL, 0,0,0,0,0);

    if (isSignWithCa){
        if (cert_item->public_key_pem!=0 && strcmp(cert_item->public_key_pem,"")!=0){
            if (cert_item->public_key_pem_size>0){
                BIO *bioCa = BIO_new(BIO_s_mem());

                BIO_write(bioCa,cert_item->public_key_pem,cert_item->public_key_pem_size);

                X509 *x509Ca=X509_new();

                PEM_read_bio_X509(bioCa,&x509Ca,0,0);

                STACK_OF(X509) *stackX509=sk_X509_new_null();
                sk_X509_push(stackX509,x509Ca);

                PKCS12_free(p12);
                p12 = PKCS12_create(passin, entries->common_name, pkey, req, stackX509, 0,0,0,0,0);

                sk_X509_pop_free(stackX509, X509_free);

                // add ca that signed the cert to p12 certificate
                //PKCS12_add_cert(p12,x509Ca);
            }
        }
    }

    /**
      * PKCS12
      */
    if (is_p12)
    {
        BIO * p12Bio = BIO_new(BIO_s_mem());
        i2d_PKCS12_bio(p12Bio,p12);
        BUF_MEM *bptrP12;
        BIO_get_mem_ptr(p12Bio, &bptrP12);
        int length3 = bptrP12->length;
        char* p12Cert = new char[length3];
        BIO_read(p12Bio,p12Cert,length3);
        certs->key_pkcs12=p12Cert;
        certs->pkcs12_key_length=length3;
        delete(p12Bio);
        delete(bptrP12);
    }

    if (is_pem && strcmp(public_key_pem_file,"")!=0){
        FILE *fp;
        if (!(fp = fopen(public_key_pem_file, "w"))){
            fprintf(stderr, "Error opening file %s\n", public_key_pem_file);
            fatal("Error writing to public key file");
        }
        if (PEM_write_X509(fp, req) != 1)
            fatal("Error while writing public key");
        fclose(fp);
    }

    if (is_pem && strcmp(private_key_pem_file,"")!=0){
        FILE *fp;
        if (!(fp = fopen(private_key_pem_file, "w"))){
            fprintf(stderr, "Error opening file %s\n", private_key_pem_file);
            fatal("Error writing to private key file");
        }

        if (strcmp(passin,"")==0){

            if (PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, 0, NULL) != 1)
                fatal("Error while writing private key");
        }
        else{
            if (PEM_write_PrivateKey(fp, pkey, EVP_aes_256_cbc(), NULL, 0, 0, passin) != 1)
                fatal("Error while writing private key");
        }
        fclose(fp);
    }

    if (is_p12 && strcmp(key_p12_file,"")!=0 )
    {
        FILE *fp1;
        if (!(fp1 = fopen(key_p12_file, "wb"))) {
            fprintf(stderr, "Error opening file %s\n", key_p12_file);
            fatal("Error writing to p12 file");
        }

        i2d_PKCS12_fp(fp1, p12);
        fclose(fp1);
    }

    EVP_PKEY_free(pkey);
    X509_free(req);
    PKCS12_free(p12);
    return 0;
}

/**
 * @brief SslGen::createCertEntry
 *      Create certificate entry and add to X509_NAME
 * @param subj
 * @param entry_key
 * @param entry_val
 */
void sslgen::createCertEntry(X509_NAME *subj,char *entry_key,char *entry_val)
{
    int nid;                  // ASN numeric identifier
    X509_NAME_ENTRY *ent;

    if ((nid = OBJ_txt2nid(entry_key)) == NID_undef){
        fprintf(stderr, "Error finding NID for %s\n", entry_key);
        fatal("Error on lookup");
    }

    string value=entry_val;

    if (!(ent = X509_NAME_ENTRY_create_by_NID(NULL, nid, MBSTRING_ASC,reinterpret_cast<unsigned char*>
        ((char*)value.data()), - 1)))
        fatal("Error creating Name entry from NID");

    if (X509_NAME_add_entry(subj, ent, -1, 0) != 1)
        fatal("Error adding entry to Name");
}

/**
 * @brief add_ext
 *      Add certificate extension
 * @param cert
 * @param issuer
 * @param nid
 * @param value
 * @return
 */
int add_ext(X509 *cert,X509* issuer, int nid, char *value)
{
    X509_EXTENSION *ex;
    X509V3_CTX ctx;

    /* This sets the 'context' of the extensions. */
    /* No configuration database */
    X509V3_set_ctx_nodb(&ctx);

    /* Issuer and subject certs: both the target since it is self signed,
     * no request and no CRL
     */
    X509V3_set_ctx(&ctx, issuer, cert, NULL, NULL, 0);
    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (!ex)
        return 0;

    X509_add_ext(cert,ex,-1);
    X509_EXTENSION_free(ex);
    return 1;
}

/**
 * @brief generateDhParamThread
 *      Thread for Diffie hellman key generation
 * @param filePath
 * @return
 */
void * generateDhParamThread(void* filePath)
{
    int g=2;//dh parameters
    DH *dh=NULL;
    dh = DH_new();
    if(!dh || !DH_generate_parameters_ex(dh, dh_key_size, g, NULL)){
       cout << "DH param has been generated !" << endl;
    }
    BIO *dhBio = BIO_new (BIO_s_mem());
    PEM_write_bio_DHparams(dhBio,dh);
    BUF_MEM *bptrDh;
    BIO_get_mem_ptr(dhBio, &bptrDh);
    int length3 = bptrDh->length;
    char dhArray[length3];
    BIO_read(dhBio,dhArray,length3);
    FILE *fp;
    if (!(fp = fopen((char*)filePath, "w")))
    {
       cout << "Error writing to dh file";
    }
    fprintf(fp,"%s",dhArray);
    fclose(fp);

    cout << "DH Params generation has finished!"<< endl;

    return 0;
}

/**
 * @brief SslGen::create_dh_key
 *      Generate Diffie Hellman key
 * @param key_size
 * @param file_path
 * @return
 */
pthread_t sslgen::create_dh_key(int key_size,char* file_path)
{
    if (file_path!=0 && strcmp(file_path,"")!=0)
    {
        dh_key_size=key_size;
        pthread_t dh_thread;
        cout << "Generate DH Params" << endl;
        int rc = pthread_create(&dh_thread, NULL,generateDhParamThread,(void*)file_path);

        if (rc){
            cout << "Error:unable to create thread," << rc << endl;
            return -1;
        }
        return dh_thread;
    }
    else{
        cout << "Error output file path is required" << endl;
    }
    return 0;
}

/**
 * @brief SslGen::fatal_error
 *      Error catch function
 * @param file
 * @param line
 * @param msg
 */
void sslgen::fatal_error(const char *file, int line, const char *msg)
{
    fprintf(stderr, "**FATAL** %s:%i %s\n", file, line, msg);
    ERR_print_errors_fp(stderr);
    exit(-1);
}

