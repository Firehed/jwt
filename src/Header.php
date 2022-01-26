<?php

declare(strict_types=1);

namespace Firehed\JWT;

/**
 * Constants for registered header parameter names in RFC7515 Section 4.1
 */
interface Header
{
    public const ALGORITHM = 'alg'; // 4.1.1
    public const JWK_SET_URL = 'jku'; // 4.1.2
    public const JSON_WEB_KEY = 'jwk'; // 4.1.3
    public const KEY_ID = 'kid'; // 4.1.4
    public const X509_URL = 'x5u'; // 4.1.5
    public const X509_CERT_CHAIN = 'x5c'; // 4.1.6
    public const X509_CERT_SHA1_THUMBPRINT = 'x5t'; // 4.1.7
    public const X509_CERT_SHA256_THUMBPRINT = 'x5t#S256'; // 4.1.8
    public const TYPE = 'typ'; // 4.1.9
}
