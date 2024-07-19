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
    case Ecdsa256 = 'ES256';
    case Ecdsa384 = 'ES384';
    case Ecdsa512 = 'ES512';
    case Pkcs256 = 'RS256';
    case Pkcs384 = 'RS384';
    case Pkcs512 = 'RS512';
    case Pss256 = 'PS256';
    case Pss384 = 'PS384';
    case Pss512 = 'PS512';

    /**
     * Constants for backwards compatibility
     */
    const NONE = Algorithm::None;
    const HMAC_SHA_256 = Algorithm::HmacSha256;
    const HMAC_SHA_384 = Algorithm::HmacSha384;
    const HMAC_SHA_512 = Algorithm::HmacSha512;
    const ECDSA_256 = Algorithm::Ecdsa256;
    const ECDSA_384 = Algorithm::Ecdsa384;
    const ECDSA_512 = Algorithm::Ecdsa512;
    const PKCS_256 = Algorithm::Pkcs256;
    const PKCS_384 = Algorithm::Pkcs384;
    const PKCS_512 = Algorithm::Pkcs512;
    const PSS_256 = Algorithm::Pss256;
    const PSS_384 = Algorithm::Pss384;
    const PSS_512 = Algorithm::Pss512;
}
