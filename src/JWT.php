<?php

declare(strict_types=1);

namespace Firehed\JWT;

use BadMethodCallException;
use Exception;
use Firehed\Security\Secret;
use RuntimeException;
use UnexpectedValueException;

/**
 * @phpstan-type Headers array{
 *   alg: Algorithm::* | null,
 *   typ: 'JWT',
 *   kid?: array-key,
 * }
 */
class JWT
{
    private bool $is_verified = false;

    private KeyContainer $keys;

    // Actual JWT components

    /**
     * @var Headers
     */
    private $headers = [
        Header::ALGORITHM => null,
        Header::TYPE => 'JWT',
    ];

    /** @var array<mixed> */
    private $claims = [];

    private string $signature;

    /**
     * @param array<string, mixed> $claims
     */
    public function __construct(array $claims = [])
    {
        $this->claims = $claims;
        $this->is_verified = true;
    } // __construct

    /** @param int|string $keyId */
    public function getEncoded($keyId = null): string
    {
        list($alg, $secret, $id) = $this->keys->getKey($keyId);
        $this->headers[Header::ALGORITHM] = $alg;
        $this->headers[Header::KEY_ID] = $id;

        $headers = self::b64encode($this->headers);
        $claims = self::b64encode($this->claims);
        $signature = self::sign($this->headers, $this->claims, $alg, $secret);
        return sprintf('%s.%s.%s', $headers, $claims, $signature);
    }

    /**
     * @return array<string, mixed>
     */
    public function getClaims(): array
    {
        // Prevent any access to the data unless verification has succeeded or
        // has been explicitly bypassed
        if ($this->is_verified) {
            return $this->claims;
        }
        if ($this->headers[Header::ALGORITHM] === Algorithm::NONE) {
            throw new BadMethodCallException(
                'This token is not verified! Either call `verify` first, or '.
                'access the unverified claims with `getUnverifiedClaims`.'
            );
        }
        throw new InvalidSignatureException("Signature is invalid");
    } // getClaims

    /**
     * @return array<string, mixed>
     */
    public function getUnverifiedClaims(): array
    {
        return $this->claims;
    }

    public function setKeys(KeyContainer $keys): self
    {
        $this->keys = $keys;
        return $this;
    }

    public static function fromEncoded(string $encoded, KeyContainer $keys): self
    {
        // This should exactly follow s7.2 of the IETF JWT spec
        $parts = explode('.', $encoded);
        if (3 !== count($parts)) {
            throw new InvalidFormatException(
                'Invalid format, wrong number of segments'
            );
        }
        list($enc_header, $enc_claims, $signature) = $parts;
        $headers = self::b64decode($enc_header);
        $claims = self::b64decode($enc_claims);

        $token = new self($claims);
        $token->headers = $headers; // @phpstan-ignore-line The headers get revalidated below
        $token->signature = $signature;
        $token->setKeys($keys);
        $token->authenticate();
        $token->enforceExpirations();
        return $token;
    }

    private function authenticate(): void
    {
        $this->is_verified = false;
        list($alg, $secret, $id) = $this->keys->getKey($this->headers['kid'] ?? null);
        // Ignore the `alg` header that was provided from the user-supplied JWT
        // in favor of the value provided by the application via the
        // KeyContainer. This prevents a common attack to bypass signature
        // validation.
        //
        // If the algorithm that came out of the application-provided key
        // container is *still* Algorithm::NONE, skip verification.
        if ($alg === Algorithm::NONE) {
            return;
        }
        $sig = self::sign($this->headers, $this->claims, $alg, $secret);
        if (hash_equals($sig, $this->signature)) {
            $this->is_verified = true;
        }
    }

    /** @return int|string|null */
    public function getKeyID()
    {
        return $this->headers[Header::KEY_ID] ?? null;
    } // getKeyID

    /**
     * @param Headers $headers
     * @param mixed[] $claims
     * @param Algorithm::* $alg
     */
    private static function sign(array $headers, array $claims, string $alg, Secret $key): string
    {
        $payload = self::b64encode($headers).
            '.'.
            self::b64encode($claims);

        switch ($alg) {
            case Algorithm::NONE:
                $data = '';
                break;
            case Algorithm::HMAC_SHA_256:
                $data = hash_hmac('SHA256', $payload, $key->reveal(), true);
                break;
            case Algorithm::HMAC_SHA_384:
                $data = hash_hmac('SHA384', $payload, $key->reveal(), true);
                break;
            case Algorithm::HMAC_SHA_512:
                $data = hash_hmac('SHA512', $payload, $key->reveal(), true);
                break;
            default:
                throw new Exception("Unsupported algorithm");
            // use openssl_sign and friends to do the signing
        }
        if ($data === false) { // @phpstan-ignore-line this is valid in PHP<=7.4
            throw new UnexpectedValueException('Payload could not be hashed');
        }
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    } // sign

    private function enforceExpirations(): void
    {
        if (isset($this->claims[Claim::EXPIRATION_TIME])) {
            $exp = $this->claims[Claim::EXPIRATION_TIME];
            if (time() >= $exp) { // 4.1.4 says "on or after"
                throw new TokenExpiredException("JWT has expired");
            }
        }
        if (isset($this->claims[Claim::NOT_BEFORE])) {
            $nbf = $this->claims[Claim::NOT_BEFORE];
            if (time() < $nbf) {
                throw new TokenNotYetValidException("JWT is not yet valid");
            }
        }
    } // enforceExpirations

    /** @return array<mixed> */
    private static function b64decode(string $base64_str): array
    {
        $json = base64_decode(strtr($base64_str, '-_', '+/'), true);
        if ($json === false) {
            throw new RuntimeException('String could not be decoded');
        }
        $decoded = json_decode($json, true);
        if (\JSON_ERROR_NONE !== json_last_error()) {
            throw new InvalidFormatException("JSON was invalid");
        }
        if (!is_array($decoded)) {
            throw new RuntimeException('Encoded JSON was not an array');
        }
        return $decoded;
    } // b64decode

    /** @param array<mixed> $data */
    private static function b64encode(array $data): string
    {
        $json = json_encode($data, \JSON_UNESCAPED_SLASHES);
        if ($json === false) {
            throw new RuntimeException('JSON encoding failed');
        }
        return rtrim(strtr(base64_encode($json), '+/', '-_'), '=');
    } // b64encode
}
