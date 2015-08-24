# SSL cert generator library #

http://akinaru.github.io/ssl-cert-generator-lib/

<i>Last update 24/08/2015</i>

Generate SSL certificates using openssl api :

* generate X509 public/private key pair, output can be PEM, PKCS12 certs
* generate self-signed cert (which can be used as CA cert)
* generate X509 public/private key pair signed with a specific issuer cert or a CA
* generate a diffie hellman key
* output can be a specific file / certificates can be accessed programmatically as well

<hr/>

<h4>Generality</h4>

Library is generated as a shared library (.dll or .so)

```
cd sslcertgenerator
make
```

Library release is under `release` directory.

You can export shared library to your library path to use it.

<hr/>

<h4>Generate self-signed certificates </h4>

Declare new instance of SslGen :
```
SslGen ssl_gen;
```

Generate self-signed certificates :
```
ssl_gen.create_standalone_keys(cert_entries *entries,struct tm *date_start,struct tm *date_end,int serial,char *passin,int rsa_key_size,certificate_raw *certs);
```

* `entries` : a set of certificate entries with following structure :
```
typedef struct {
    char *country_name;
    char *state_province_name;
    char *locality_name;
    char *organization_name;
    char *organizational_unit_name;
    char *common_name;
} cert_entries;
```
* `date_start` and `date_end` specifying certificate validation timings
* `serial` : specifying certificate serial number to be used
* `passin` : optional password for private key
* `rsa_key_size` : size of key (2048 or more is prefered)
* `certificate_raw` : output pointer structure as following :
```
typedef struct {
    char *public_key_pem;
    int public_key_pem_length;
    char *private_key_pem;
    int private_key_pem_length;
    char *key_pkcs12;
    int pkcs12_key_length;
} certificate_raw;

```

<h4>Generate signed certificates </h4>

```
ssl_gen.create_signed_keys(cert_entries *entries,struct tm *date_start,struct tm *date_end,int serial,char *passin,int rsa_key_size,ca_cert *cert_item,certificate_raw *certs);
```
* `entries` : a set of certificate entries with following structure :
```
typedef struct {
    char *country_name;
    char *state_province_name;
    char *locality_name;
    char *organization_name;
    char *organizational_unit_name;
    char *common_name;
} cert_entries;
```
* `date_start` and date_end specifying certificate validation timings
* `serial` : specifying certificate serial number to be used
* `passin` : optional password for private key
* `rsa_key_size` : size of key (2048 or more is prefered)
* `ca_cert` : structure defining public/private key of CA cert or cert issuer
```
typedef struct{
    char *public_key_pem;
    int public_key_pem_size;
    char *private_key_pem;
    int private_key_pem_size;
    char *pass;
} ca_cert;
```

* `certificate_raw` : output pointer structure as following :

```
typedef struct {
    char *public_key_pem;
    int public_key_pem_length;
    char *private_key_pem;
    int private_key_pem_length;
    char *key_pkcs12;
    int pkcs12_key_length;
} certificate_raw;
```

<h4>Specify output format and file output</h4>

By default public and private key are given in PEM format.
By default, no output file path is specified.

You can specify cert output files for PEM cert as following :

```
ssl_gen.setOutputPEM(bool enable_pem,char* public_key_file,char* private_key_file);
```

* `enable_pem` : enable PEM format (default)
* `public_key_file` : output file for public key in PEM format
* `private_key_file` : output file for private key in PEM format

You can specify cert output files for PKCS12 cert as following :

```
ssl_gen.setOutputP12(bool enable_p12,char* key_file);
```

* `enable_p12` : enable PKCS12 format
* `key_file` : output file for public/private key in PKCS12 format

<h4>Generate DH key</h4>

Generate Diffie-Hellman key with :

```
ssl_gen.create_dh_key(int key_size,char* file_path);
```
* `key_size` : key size to be used (2048 is preferred)
* `file_path` : required output file path for the key

<b>Examples</b>

[From test project in main.cpp](https://github.com/ssl-cert-generator-lib/blob/master/sslcertgenerator/main.cpp)

<i>Generate self-signed certificates</i>

```

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

```

<i>Generate signed certificate</i>

```

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


```

<h4>Checking and Verifying certificates</h4>

Here are some useful openssl command to test your output :

<i>Check start date and end date for a PEM certificate</i>

* `openssl x509 -startdate -noout -in cert.crt`
* `openssl x509 -enddate -noout -in cert.crt`

<i>Check a public PEM key</i>

* openssl x509 -in cert.crt -text -noout

<i>Check a private PEM key</i>

* openssl rsa -in cert.key -check

<i>Check a PKCS12 file</i>

* openssl pkcs12 -info -in cert.p12

<i>Check that public/key pair is uncorrupted</i>

Those commands should return same md5 : 
* `openssl x509 -noout -modulus -in cert.crt | openssl md5`
* `openssl rsa -noout -modulus -in cert.key | openssl md5`

<i>Verify certificate</i>

* `openssl verify cert.pem`

<i>Verify certificate chain</i>

* `openssl verify -CAfile ca.crt server.crt`

<i>Install certificates on Linux</i>

```
sudo mkdir /usr/share/ca-certificates/extra

sudo cp your_cert.pem /usr/share/ca-certificates/extra/your_cert.crt

sudo dpkg-reconfigure ca-certificates

sudo update-ca-certificates
```

<hr/>

<b>TODO</b>

* add static library
* add certificate extensions
* add CA certificate to PKCS12 for signed certificate
* add pass for PKCS12 (distinguished from private key)
