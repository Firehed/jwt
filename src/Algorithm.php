<?php

namespace Firehed\JWT;

use Firehed\Common\Enum;

class Algorithm extends Enum {

    const NONE = 0;
    const HMAC_SHA_256 = 1;
    const HMAC_SHA_384 = 2;
    const HMAC_SHA_512 = 3;
    const ECDSA_256 = 4;
    const ECDSA_384 = 5;
    const ECDSA_512 = 6;
    const PKCS_256 = 7;
    const PKCS_384 = 8;
    const PKCS_512 = 9;
    const PSS_256 = 10;
    const PSS_384 = 11;
    const PSS_512 = 12;

}
