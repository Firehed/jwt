<?php

namespace Firehed\JWT;

use Firehed\Common\Enum;

class Algorithm extends Enum {

    const NONE = 'none';
    const HMAC_SHA_256 = 'HS256';
    const HMAC_SHA_384 = 'HS384';
    const HMAC_SHA_512 = 'HS512';
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
