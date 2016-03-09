<?php

namespace Firehed\JWT;

use Exception;
use BadMethodCallException;

class JWT {

    private $headers = [
        'alg' => null,
        'typ' => 'JWT',
    ];

    private $claims = [];

    private $signature = '';

    private $is_verified = false;

    public static function decode($encoded_token, Algorithm $alg = null, $key = null) {
        // This should exactly follow s7.2 of the IETF JWT spec
        $parts = explode('.', $encoded_token);
        if (3 !== count($parts)) {
            throw new InvalidFormatException(
                'Invalid format, wrong number of segments');
        }
        list($enc_header, $enc_claims, $signature) = $parts;
        $headers = self::b64decode($enc_header);
        $claims = self::b64decode($enc_claims);
        $token = new self($claims);
        $token->is_verified = false;
        $token->headers = $headers;
        $token->signature = $signature;
        if ($key) {
            $token->verify($alg, $key);
        }
        $token->enforceExpirations();
        return $token;
    } // decode

    public function __construct(array $claims = []) {
        $this->claims = $claims;
        $this->is_verified = true;
    } // __construct

    public function getUnverifiedClaims() {
        return $this->claims;
    }

    public function getClaims() {
        // Prevent any access to the data unless verification has succeeded or
        // has been explicitly bypassed
        if ($this->is_verified) {
            return $this->claims;
        }
        throw new BadMethodCallException(
            'This token is not verified! Either call `verify` first, or '.
            'access the unverified claims with `getUnverifiedClaims`.');
    } // getClaims

    public function isSigned() {
        return !$this->getAlgorithm()->is(Algorithm::NONE());
    } // isSigned

    private function enforceExpirations() {
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

    /**
     * The algorithm is explicitly provided to the verification process to
     * prevent algorithm-switching attacks. The value should be either
     * hard-coded into the codebase, or (more preferably) derived from the
     * "kid" (key ID) header value
     */
    public function verify(Algorithm $alg, $key) {
        if ($alg->is(Algorithm::NONE())) {
            return;
        }
        $this->setAlgorithm($alg);
        $enc_exp_hash = $this->sign($key);
        if (self::hashEquals($enc_exp_hash, $this->signature)) {
            $this->is_verified = true;
            return true;
        }
        $this->is_verified = false;
        throw new InvalidSignatureException("Signature is invalid");
    } // verify

    private static function hashEquals($expected, $provided) {
        if (function_exists('hash_equals')) {
            return hash_equals($expected, $provided);
        }
        // Fall back to self-rolled slow compare

        // This will always be in constant time relative to the expected
        // signature of the data (rather than the user-supplied data, since
        // they know the hashing algorithm in this very specific use case)
        $mod = strlen($provided);
        $ret = 0;
        for ($i = 0, $stop = strlen($expected); $i < $stop; $i++) {
            $ret |= (ord($provided[$i % $mod]) ^ ord($expected[$i]));
        }
        return $ret === 0;
    } // hashEquals

    public function encode($key) {
        $headers = self::b64encode($this->headers);
        $claims = self::b64encode($this->claims);
        $sig = $this->sign($key);
        return "$headers.$claims.$sig";
    } // encode

    private function sign($key) {
        $alg = $this->getAlgorithm();

        $payload = self::b64encode($this->headers).
            '.'.
            self::b64encode($this->claims);

        switch ($alg()) {
        case Algorithm::NONE:
            $data = '';
            break;
        case Algorithm::HMAC_SHA_256:
            $data = hash_hmac('SHA256', $payload, $key, true);
            break;
        case Algorithm::HMAC_SHA_384:
            $data = hash_hmac('SHA384', $payload, $key, true);
            break;
        case Algorithm::HMAC_SHA_512:
            $data = hash_hmac('SHA512', $payload, $key, true);
            break;
        default:
            throw new Exception("Unsupported algorithm");
            // use openssl_sign and friends to do the signing
        }
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    } // sign

    private static function b64decode($base64_str) {
        $json = base64_decode(strtr($base64_str, '-_', '+/'));
        $decoded = json_decode($json, true);
        if (\JSON_ERROR_NONE !== json_last_error()) {
            throw new InvalidFormatException("JSON was invalid");
        }
        return $decoded;
    } // b64decode

    private static function b64encode($data) {
        $json = json_encode($data, \JSON_UNESCAPED_SLASHES);
        return rtrim(strtr(base64_encode($json), '+/', '-_'), '=');
    } // b64encode

    private function getAlgorithm() {
        if (!isset($this->headers['alg'])) {
            throw new JWTException("Algorithm is not specified");
        }
        // This will error out if the algorithm is invalid
        return new Algorithm($this->headers['alg']);
    } // getAlgorithm

    public function setAlgorithm(Algorithm $alg) {
        $this->headers['alg'] = $alg->getValue();
        return $this;
    } // setAlgorithm

    public function getKeyID() {
        return isset($this->headers['kid'])
            ? $this->headers['kid']
            : null;
    } // getKeyID

    public function setKeyID($key_id) {
        $this->headers['kid'] = $key_id;
        return $this;
    } // setKeyID
}
