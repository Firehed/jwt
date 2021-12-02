<?php

namespace Firehed\JWT;

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
}
