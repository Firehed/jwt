<?php

declare(strict_types=1);

namespace Firehed\JWT;

/**
 * Constants for registered claims in RFC7519 Section 4.1
 */
interface Claim
{
    public const ISSUER = 'iss'; // 4.1.1
    public const SUBJECT = 'sub'; // 4.1.2
    public const AUDIENCE = 'aud'; // 4.1.3
    public const EXPIRATION_TIME = 'exp'; // 4.1.4
    public const NOT_BEFORE = 'nbf'; // 4.1.5
    public const ISSUED_AT = 'iat'; // 4.1.6
    public const JWT_ID = 'jti'; // 4.1.7
}
