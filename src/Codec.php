<?php

declare(strict_types=1);

namespace Firehed\JWT;

use SensitiveParameter;

/**
 * Convenience wrapper for key management. The intent is to set up an instance
 * of this class once in your application's DI container, and pass it around
 * (rather than the key container) for all operations.
 */
class Codec
{
    private KeyContainer $keys;

    public function __construct(KeyContainer $keys)
    {
        $this->keys = $keys;
    }

    /**
     * @param array<string, mixed> $claims
     * @param int|string|null $keyId
     */
    public function encode(array $claims, $keyId = null): string
    {
        $jwt = new JWT($claims);
        $jwt->setKeys($this->keys);
        return $jwt->getEncoded($keyId);
    }

    public function decode(
        #[SensitiveParameter]
        string $jwt
    ): JWT {
        return JWT::fromEncoded($jwt, $this->keys);
    }
}
