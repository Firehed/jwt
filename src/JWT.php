<?php

namespace Firehed\JWT;

use BadMethodCallException;
use Exception;
use Firehed\Security\Secret;
use RuntimeException;

class JWT
{

    /** @var bool */
    private $is_verified = false;

    /** @var KeyContainer */
    private $keys;

    // Actual JWT components
    /** @var array<string, mixed> */
    private $headers = [
        'alg' => null,
        'typ' => 'JWT',
    ];

    /** @var array<mixed> */
    private $claims = [];

    /** @var string */
    private $signature;

    public function __construct(array $claims = [])
    {
        $this->claims = $claims;
        $this->is_verified = true;
    } // __construct

    /** @param int|string $keyId */
    public function getEncoded($keyId = null): string
    {
        if ($this->keys === null) {
            throw new BadMethodCallException(
                'No keys have been provided to this JWT. Call setKeys() '.
                'before using getEncoded().'
            );
        }
        list($alg, $secret, $id) = $this->keys->getKey($keyId);
        $this->headers['alg'] = $alg->getValue();
        $this->headers['kid'] = $id;

        $headers = self::b64encode($this->headers);
        $claims = self::b64encode($this->claims);
        $signature = $this->sign($secret);
        return sprintf('%s.%s.%s', $headers, $claims, $signature);
    }

    public function getClaims(): array
    {
        // Prevent any access to the data unless verification has succeeded or
        // has been explicitly bypassed
        if ($this->is_verified) {
            return $this->claims;
        }
        if ($this->headers['alg'] === Algorithm::NONE) {
            throw new BadMethodCallException(
                'This token is not verified! Either call `verify` first, or '.
                'access the unverified claims with `getUnverifiedClaims`.'
            );
        }
        throw new InvalidSignatureException("Signature is invalid");
    } // getClaims

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
        $token->headers = $headers;
        $token->signature = $signature;
        $token->setKeys($keys);
        $token->authenticate();
        $token->enforceExpirations();
        return $token;
    }

    /** @return void */
    private function authenticate()
    {
        $this->is_verified = false;
        list($alg, $secret, $id) = $this->keys->getKey($this->headers['kid'] ?? null);
        // Always verify against known algorithm from key container + key id
        $this->headers['alg'] = $alg->getValue();
        if ($this->headers['alg'] === Algorithm::NONE) {
            return;
        }
        $sig = $this->sign($secret);
        if (hash_equals($sig, $this->signature)) {
            $this->is_verified = true;
        }
    }

    /** @return int|string|null */
    public function getKeyID()
    {
        return $this->headers['kid'] ?? null;
    } // getKeyID

    private function sign(Secret $key): string
    {
        $alg = $this->headers['alg']; // DEFAULT?

        $payload = self::b64encode($this->headers).
            '.'.
            self::b64encode($this->claims);

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
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    } // sign

    /** @return void */
    private function enforceExpirations()
    {
        if (isset($this->claims['exp'])) {
            $exp = $this->claims['exp'];
            if (time() >= $exp) { // 4.1.4 says "on or after"
                throw new TokenExpiredException("JWT has expired");
            }
        }
        if (isset($this->claims['nbf'])) {
            $nbf = $this->claims['nbf'];
            if (time() < $nbf) {
                throw new TokenNotYetValidException("JWT is not yet valid");
            }
        }
    } // enforceExpirations

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
        return $decoded;
    } // b64decode

    private static function b64encode(array $data): string
    {
        $json = json_encode($data, \JSON_UNESCAPED_SLASHES);
        if ($json === false) {
            throw new RuntimeException('JSON encoding failed');
        }
        return rtrim(strtr(base64_encode($json), '+/', '-_'), '=');
    } // b64encode
}
