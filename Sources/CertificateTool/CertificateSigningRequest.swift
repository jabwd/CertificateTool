//
//  CertificateRequest.swift
//  CertificateToolPackageDescription
//
//  Created by Antwan van Houdt on 10/01/2018.
//

import CLibreSSL

public enum NIDType: String {
    case email    = "emailAddress"
    case hostName = "CN"
    case organizationalUnit = "OU"
    case organization      = "O"
    case city        = "L"
    case state       = "ST"
    case countryCode = "C"
}

public class CertificateSigningRequest {
    private let request: UnsafeMutablePointer<X509_REQ>
    private let key:     ECKey
    private let name:    UnsafeMutablePointer<X509_NAME>
    
    public init(key: ECKey, email: String, hostName: String, organizationalUnit: String, organization: String, countryCode: String, state: String, city: String) {
        request = X509_REQ_new()
        self.key = key
        
        name = X509_NAME_new()
        X509_REQ_set_version(request, 2)
        
        self.add(name: email, type: .email)
        self.add(name: hostName, type: .hostName)
        self.add(name: organizationalUnit, type: .organizationalUnit)
        self.add(name: organization, type: .organization)
        self.add(name: countryCode, type: .countryCode)
        self.add(name: city, type: .city)
        self.add(name: state, type: .state)
        
        X509_REQ_set_subject_name(request, name)
        
        self.setPublicKey()
    }
    
    deinit {
        X509_REQ_free(request)
        X509_NAME_free(name)
    }
    
    private func add(name: String, type: NIDType) {
        var buff = Array(name.utf8)
        X509_NAME_add_entry_by_NID(self.name, OBJ_txt2nid(type.rawValue), MBSTRING_UTF8, &buff, Int32(buff.count), 0, 0)
    }
    
    private func setPublicKey() {
        let certKey = EVP_PKEY_new()
        EVP_PKEY_set1_EC_KEY(certKey, key.secretKey)
        
        X509_REQ_set_pubkey(request, certKey)
        X509_REQ_sign(request, certKey, EVP_sha256())
        
        EVP_PKEY_free(certKey)
    }
}
