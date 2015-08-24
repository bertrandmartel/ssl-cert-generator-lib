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
    main.cpp
    
    Generate certificates from openssl api :
    * self signed certificates public/private keys
    * signed certificates
    * diffie hellman key

    @author Bertrand Martel
    @version 1.0
*/
#include "crypto/sslgen.h"
#include <iostream>
#include "crypto/utils.h"
#include <fstream>
#include <cstring>

#define CERT_COUNTRY_NAME           "FR"
#define CERT_STATE_OR_PROVINCE_NAME "IDF"
#define CERT_LOCALITY_NAME          "Paris"
#define CERT_ORGANIZATION_NAME      "GITHUB"
#define CERT_ORGANIZATION_UNIT_NAME "IT"

using namespace std;

int main(int argc, char *argv[]){

    cout << "generate keys..." << endl;

    /*instanciate certificate generation lib*/
    sslgen ssl_gen;

    /* get system time for date start*/
    time_t systime;
    struct tm *sys_time;
    time(&systime);
    sys_time=localtime(&systime);

    /* set end date to 30/08/2019 00:00:00 (current timezone)*/
    struct tm  date_end;
    date_end.tm_year = 2019 - 1900;
    date_end.tm_mon = 8 - 1;
    date_end.tm_mday = 30;
    date_end.tm_hour = 0;
    date_end.tm_min = 0;
    date_end.tm_sec = 0;
    date_end.tm_isdst = sys_time->tm_isdst;

    /*set certificate entries*/
    cert_entries entries;
    entries.country_name=CERT_COUNTRY_NAME;
    entries.state_province_name=CERT_STATE_OR_PROVINCE_NAME;
    entries.locality_name=CERT_LOCALITY_NAME;
    entries.organization_name=CERT_ORGANIZATION_NAME;
    entries.organizational_unit_name=CERT_ORGANIZATION_UNIT_NAME;

    /* generate public/private key (we want PEM + PKCS12 format) + output is retrieved through input pointer + file output name*/

    /*set output cert as pem certificate (default). If you set file output name. Cert will be written under these files*/
    ssl_gen.setOutputPEM(true,"../../output_test/test.crt","../../output_test/test.key");

    /*set output cert as p12 certificate. If you set file output name. Cert will be written under these files*/
    ssl_gen.setOutputP12(true,"../../output_test/test.p12");

    certificate_raw certs;
    certificate_raw *certs_ptr;
    certs_ptr=&certs;
    certs_ptr->public_key_pem="";
    certs_ptr->private_key_pem="";
    certs_ptr->key_pkcs12="";

    entries.common_name="Github ssl-cert-generator";

    /* generate standalone keys (not signed with other certificate) */
    ssl_gen.create_standalone_keys(&entries,sys_time,&date_end,509,"123456",2048,&certs);

    cout << "public cert  : " << certs_ptr->public_key_pem << endl;
    cout << "private cert : " << certs_ptr->private_key_pem << endl;
    cout << "p12 binary content : " << endl;
    utils::printHexFormattedCert(certs_ptr->key_pkcs12,certs_ptr->pkcs12_key_length);

    cout << "##########################################################" << endl;

    std::ifstream in1("../../cert/ca.key");
    std::string root_ca_key_input((std::istreambuf_iterator<char>(in1)),std::istreambuf_iterator<char>());

    std::ifstream in2("../../cert/ca.crt");
    std::string root_ca_pub_input((std::istreambuf_iterator<char>(in2)),std::istreambuf_iterator<char>());

    /*set output cert as pem certificate (default). If you set file output name. Cert will be written under these files*/
    ssl_gen.setOutputPEM(true,"../../output_test/client.crt","../../output_test/client.key");

    /*set output cert as p12 certificate. If you set file output name. Cert will be written under these files*/
    ssl_gen.setOutputP12(true,"../../output_test/client.p12");

    ca_cert ca;
    char *pub = new char[root_ca_pub_input.length() + 1];
    strcpy(pub, root_ca_pub_input.c_str());
    char *key = new char[root_ca_key_input.length() + 1];
    strcpy(key, root_ca_key_input.c_str());
    ca.public_key_pem=pub;
    ca.public_key_pem_size=root_ca_pub_input.length();
    ca.private_key_pem=key;
    ca.private_key_pem_size=root_ca_key_input.length();
    ca.pass="123456";

    entries.common_name="Github ssl-cert-generator signed cert";

    ssl_gen.create_signed_keys(&entries,sys_time,&date_end,22555,"123456",2048,&ca,&certs);

    cout << "public cert  : " << certs_ptr->public_key_pem << endl;
    cout << "private cert : " << certs_ptr->private_key_pem << endl;
    cout << "p12 binary content : " << endl;
    utils::printHexFormattedCert(certs_ptr->key_pkcs12,certs_ptr->pkcs12_key_length);

    cout << "##########################################################" << endl;

    /*CA certificate used to sign keys*/

    pthread_t thread = ssl_gen.create_dh_key(1024,"../../output_test/dh.key");

    /*wait for thread to finish*/
    int rc = pthread_join(thread, NULL);

    return 0;
}
