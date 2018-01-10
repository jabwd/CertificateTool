//
//  ECKey.swift
//  CertificateToolPackageDescription
//
//  Created by Antwan van Houdt on 10/01/2018.
//

import CLibreSSL

public class ECKey {
    internal let secretKey: OpaquePointer
    private let group: OpaquePointer
    
    public init() {
        group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)
        EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE)
        EC_GROUP_set_point_conversion_form(group, POINT_CONVERSION_COMPRESSED)
        
        secretKey = EC_KEY_new()
        EC_KEY_set_group(secretKey, group)
        EC_KEY_generate_key(secretKey)
    }
    
    deinit {
        EC_KEY_free(secretKey)
        EC_GROUP_free(group)
    }
}
