<?php

namespace Firehed\JWT;

use Exception;

class JWT {

    private $headers = [];
    private $claims = [];

    public static function decode($encoded_token, $key = null) {
        // This should exactly follow s7.2 of the IETF JWT spec
        $parts = explode('.', $encoded_token);
        if (3 !== count($parts)) {
            throw new InvalidFormatException(
                'Invalid format, wrong number of segments');
        }
        list($enc_header, $enc_claims, $signature) = $parts;
        $header = self::b64decode($enc_header);
        $claims = self::b64decode($enc_claims);
        $token = new self($header, $claims);
        if (!$token->verify($signature, $key)) {
            throw new InvalidSignatureException("Signature is invalid");
        }
        $token->enforceExpirations();
        return $token;
    }


    public function __construct(array $headers = [], array $claims = []) {
        $this->headers = $headers;
        $this->claims = $claims;
    } // __construct

    public function getClaims() {
        return $this->claims;
    }

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

    private function verify($signature, $key) {
        $enc_exp_hash = $this->sign($key);
        return self::hashEquals($enc_exp_hash, $signature);
    }

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
            $data = self::HMAC('SHA256', $payload, $key);
            break;
        case Algorithm::HMAC_SHA_384:
            $data = self::HMAC('SHA384', $payload, $key);
            break;
        case Algorithm::HMAC_SHA_512:
            $data = self::HMAC('SHA512', $payload, $key);
            break;
        default:
            throw new Exception("Unsupported algorithm");
            // use openssl_sign and friends to do the signing
        }
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    } // sign

    private static function HMAC($alg, $payload, $key) {
        return hash_hmac($alg, $payload, $key, true);
    } // HMAC

    private static function b64decode($base64_str) {
        $json = base64_decode(strtr($base64_str, '-_', '+/'));
        $decoded = json_decode($json, true);
        if (\JSON_ERROR_NONE !== json_last_error()) {
            throw new InvalidFormatException("JSON was invalid");
        }
        return $decoded;
    } // b64decode

    private static function b64encode(array $data) {
        $json = json_encode($data);
        return rtrim(strtr(base64_encode($json), '+/', '-_'), '=');
    } // b64encode

    private function getAlgorithm() {
        if (!isset($this->headers['alg'])) {
            throw new JWTException("Algorithm is not specified");
        }
        $alg = $this->headers['alg'];
        if (!isset(self::$alg_to_algorithm[$alg])) {
            throw new Exception("Algorithm is invalid");
        }
        $value = new Algorithm(self::$alg_to_algorithm[$alg]);
        return $value;
    } // getAlgorithm

    private static $alg_to_algorithm = [
        'none' => Algorithm::NONE,
        'HS256' => Algorithm::HMAC_SHA_256,
        'HS384' => Algorithm::HMAC_SHA_384,
        'HS512' => Algorithm::HMAC_SHA_512,
        'ES256' => Algorithm::ECDSA_256,
        'ES384' => Algorithm::ECDSA_384,
        'ES512' => Algorithm::ECDSA_512,
        'RS256' => Algorithm::PKCS_256,
        'RS384' => Algorithm::PKCS_384,
        'RS512' => Algorithm::PKCS_512,
        'PS256' => Algorithm::PSS_256,
        'PS384' => Algorithm::PSS_384,
        'PS512' => Algorithm::PSS_512,
    ];

}
