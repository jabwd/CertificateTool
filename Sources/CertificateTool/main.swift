import CLibreSSL
import Foundation

let testRequest = """
-----BEGIN CERTIFICATE REQUEST-----
MIIBXTCCAQICAQAwgZ8xCzAJBgNVBAYTAk5MMRUwEwYDVQQIDAxOb3J0aEhvbGxh
bmQxEDAOBgNVBAcMB0Fsa21hYXIxFTATBgNVBAoMDE1ETGlua2luZ09yZzEWMBQG
A1UECwwNQ29tcHV0ZXJTdHVmZjEWMBQGA1UEAwwNbWRsaW5raW5nLmNvbTEgMB4G
CSqGSIb3DQEJARYRamFid2RAZXh1cmlvbi5jb20wWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAASjzIRqOaA1rd2Je+YFj+K17GaRccS2YsX7TlhD0Job5Wmeg6IFfz9S
LebxHGIb0hqwkMNt05njxAoAcHlpK58koAAwCgYIKoZIzj0EAwIDSQAwRgIhAKyz
vwPLvPAWCsQBe3K6OOdVej5jEiVzBWP/8YrkHB7EAiEAtglSOVit1FL+mOyQxBlR
YafNGCYKdtqbj9ShYuOxcw4=
-----END CERTIFICATE REQUEST-----
"""
let testPublicKey = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDgSofItOjR0Be5pS2WjaZURr3LTl
nYnQFUo46X7qG+ans+NZYQjAy5dzzLzS6P7Lyt57fJM7CN1HZDdHXTsWyw==
-----END PUBLIC KEY-----
"""

OPENSSL_add_all_algorithms_conf()
SSL_load_error_strings()
ERR_load_ERR_strings()

let inFormat = 3 // FORMAT_PEM = 3

let curveID = NID_X9_62_prime256v1

let output = BIO_new(BIO_s_file())
let raw = UnsafeMutableRawPointer(mutating: "ec-key.pem")
BIO_ctrl(output, BIO_C_SET_FILENAME, Int(BIO_CLOSE | BIO_FP_WRITE), raw)

let ecGroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)
EC_GROUP_set_asn1_flag(ecGroup, OPENSSL_EC_NAMED_CURVE)
EC_GROUP_set_point_conversion_form(ecGroup, POINT_CONVERSION_COMPRESSED)

PEM_write_bio_ECPKParameters(output, ecGroup)

let ecKey = EC_KEY_new()
EC_KEY_set_group(ecKey, ecGroup) // 0 = failure
EC_KEY_generate_key(ecKey) // false = failure

// Finally write the private key:
PEM_write_bio_ECPrivateKey(output, ecKey, nil, nil, 0, nil, nil)
//PEM_write_bio_EC_PUBKEY(output, ecKey)

// Step1: load key
let cipher = EVP_aes_256_gcm()
let digest = EVP_sha256()
let x509ss  = X509_new()
let request = X509_REQ_new()
var ctx: X509V3_CTX = X509V3_CTX(flags: 0, issuer_cert: nil, subject_cert: nil, subject_req: nil, crl: nil, db_meth: nil, db: nil)
X509V3_set_ctx(&ctx, nil, nil, request, nil, 0)

// Setup private key for reading
let privKey = BIO_new(BIO_s_file())

// Setup BIO for writing out a csr file
let csrOut = BIO_new(BIO_s_file())
BIO_ctrl(csrOut, BIO_C_SET_FILENAME, Int(BIO_CLOSE | BIO_FP_WRITE), UnsafeMutableRawPointer(mutating: "certificate-request.csr"))

// Set version and generate a new serial number
X509_set_version(x509ss, 2) // Version V3
ASN1_INTEGER_new()
var bigNum = BN_new()
BN_pseudo_rand(bigNum, 64, 0, 0)
var serialNumber = ASN1_INTEGER(length: 0, type: 0, data: nil, flags: 0)
BN_to_ASN1_INTEGER(bigNum, &serialNumber)
BN_free(bigNum)
X509_set_serialNumber(x509ss, &serialNumber)

X509_REQ_set_version(request, 2)

// Set up the name
let name = X509_NAME_new()

let email = "jabwd@exurion.com"
let hostName = "exurion.com"
let organizationalUnit = "ComputerGenerated"
let province = "North Holland"
let city = "Alkmaar"
let organization = "ExurionInc."
let countryCode = "NL"

var buff = Array(email.utf8)
X509_NAME_add_entry_by_NID(name, OBJ_txt2nid("emailAddress"), MBSTRING_UTF8, &buff, Int32(buff.count), 0, 0)
buff = Array(hostName.utf8)
X509_NAME_add_entry_by_NID(name, OBJ_txt2nid("CN"), MBSTRING_UTF8, &buff, Int32(buff.count), 0, 0)
buff = Array(organizationalUnit.utf8)
X509_NAME_add_entry_by_NID(name, OBJ_txt2nid("OU"), MBSTRING_UTF8, &buff, Int32(buff.count), 0, 0)
buff = Array(organization.utf8)
X509_NAME_add_entry_by_NID(name, OBJ_txt2nid("O"), MBSTRING_UTF8, &buff, Int32(buff.count), 0, 0)
buff = Array(city.utf8)
X509_NAME_add_entry_by_NID(name, OBJ_txt2nid("L"), MBSTRING_UTF8, &buff, Int32(buff.count), 0, 0)
buff = Array(province.utf8)
X509_NAME_add_entry_by_NID(name, OBJ_txt2nid("ST"), MBSTRING_UTF8, &buff, Int32(buff.count), 0, 0)
buff = Array(countryCode.utf8)
X509_NAME_add_entry_by_NID(name, OBJ_txt2nid("C"), MBSTRING_UTF8, &buff, Int32(buff.count), 0, 0)

X509_REQ_set_subject_name(request, name)

let certKey = EVP_PKEY_new()
EVP_PKEY_set1_EC_KEY(certKey, ecKey!)


X509_REQ_set_pubkey(request, certKey)
if X509_REQ_sign(request, certKey, digest) == 0 {
    print("Signing the thing failed")
}

// Finally, write the CSR:
PEM_write_bio_X509_REQ(csrOut, request)
BIO_free_all(csrOut)

EC_KEY_free(ecKey)
BIO_free_all(output)

