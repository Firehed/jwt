<?php

namespace Firehed\JWT;

use Exception;

class JWT {

    private $headers = [];
    private $claims = [];


    private static $supported_algos = [
        'HS256' => 'HMAC',
        'HS384' => 'HMAC',
        'HS512' => 'HMAC',
//        'RS256' => 'OSSL',
//        'RS384' => 'OSSL',
//        'RS512' => 'OSSL',
        'none'  => 'none',
    ];

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

    public function getHeaders() {
        return $this->headers;
    }
    public function getClaims() {
        return $this->claims;
    }

    public function isSigned() {
        return $this->headers['alg'] != 'none';
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
        $algorithm = $this->headers['alg'];
        $family = self::$supported_algos[$algorithm];
        $size = substr($algorithm, 2); // this will be wrong for 'none' but ignored so it doesn't matter

        switch ($family) {
        case 'none':
            return '';
        case 'HMAC':
            $exp_hash = hash_hmac('SHA'.$size,
                self::b64encode($this->headers).'.'.self::b64encode($this->claims),
                $key,
                true);
            return rtrim(strtr(base64_encode($exp_hash), '+/', '-_'), '=');
        case 'OSSL':
            throw new Exception("OpenSSL not ready yet");
            // use openssl_sign and friends to do the signing

        }

        // Fixme: respect the algorithm
    } // sign

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

}
