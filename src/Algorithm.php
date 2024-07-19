<?php

namespace Firehed\JWT;

/**
 * Constants for algorithm header parameter values in RFC7518 Section 3.1
 */
enum Algorithm: string
{
    case None = 'none';
    case HmacSha256 = 'HS256';
    case HmacSha384 = 'HS384';
    case HmacSha512 = 'HS512';

    const NONE = Algorithm::None;
    const HMAC_SHA_256 = Algorithm::HmacSha256;
    const HMAC_SHA_384 = Algorithm::HmacSha384;
    const HMAC_SHA_512 = Algorithm::HmacSha512;
    const ECDSA_256 = 'ES256';
    const ECDSA_384 = 'ES384';
    const ECDSA_512 = 'ES512';
    const PKCS_256 = 'RS256';
    const PKCS_384 = 'RS384';
    const PKCS_512 = 'RS512';
    const PSS_256 = 'PS256';
    const PSS_384 = 'PS384';
    const PSS_512 = 'PS512';
}
