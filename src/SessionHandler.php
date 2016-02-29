<?php

namespace Firehed\JWT;

use InvalidArgumentException;
use OverflowException;
use SessionHandlerInterface;

class SessionHandler implements SessionHandlerInterface
{

    const CLAIM = 'sd';
    const DEFAULT_COOKIE = 'jwt_sid';

    private $cookie = self::DEFAULT_COOKIE;
    private $secrets = [];
    private $writer = 'setcookie';

    /**
     * Provide an array of key IDs and their associated algorithms and secrets
     *
     * Note that Algorithm::NONE is explicitly blocked, since this would
     * produce an unsigned JWT allowing users to modify their own session data.
     *
     * @param [ key id  => ['alg' => Algorithm, 'secret' => string]]
     */
    public function __construct(array $secrets) {
        array_map([$this,'verifySecret'], $secrets);
        $this->secrets = $secrets;
    }

    /**
     * Validates that each of the secrets provided in the constructor have
     * appropriate signing/verifying data.
     *
     * @param array
     * @return void
     * @throws InvalidArgumentException if the formatting is wrong
     */
    private function verifySecret(array $secret) {
        if (empty($secret['alg']) || empty($secret['secret'])) {
            throw new InvalidArgumentException(
                'Each element must be an array containing "algorithm" and "secret"');
        }
        if (!$secret['alg'] instanceof Algorithm) {
            throw new InvalidArgumentException(sprintf(
                "Algorithm must be an instance of %s, %s given",
                Algorithm::class,
                is_object($secret['alg']) ? get_class($secret['alg'])
                                          : gettype($secret['alg'])
            ));
        }
        if ($secret['alg']->is(Algorithm::NONE())) {
            throw new InvalidArgumentException(
                'Algorithm cannot be "none"');
        }
        if (!is_string($secret['secret'])) {
            throw new InvalidArgumentException(sprintf(
                'Secret must be a string, %s given',
                is_object($secret['secret']) ? get_class($secret['secret'])
                                             : gettype($secret['secret'])
            ));
        }
    }

    /**
     * No-op, interface adherence only
     * @return bool true, always
     */
    public function close() {
        return true;
    }

    public function destroy($session_id) {
        ($this->writer)($this->cookie, '', time()-86400); // Expire yesterday
        return true;
    }

    /**
     * No-op, interface adherence only
     * @return bool true, always
     */
    public function gc($maxlifetime) {
        return true;
    }

    /**
     * No-op, interface adherence only
     * @return bool true, always
     */
    public function open($save_path, $name) {
        return true;
    }

    /**
     * Reads the session data from the cookie, verifies its authenticity, and
     * returns the data to be natively unserialized into the $_SESSION
     * superglobal
     *
     * @param session_id (unused)
     * @return string the serialized session string
     * @throws JWTException if JWT processing fails, tampering is detected, etc
     */
    public function read($session_id) {
        // session_id is intentionally ignored
        if (empty($_COOKIE[$this->cookie])) {
            return '';
        }
        $encoded = $_COOKIE[$this->cookie];
        $jwt = JWT::decode($encoded);
        list($alg, $key) = $this->getSecret($jwt->getKeyID());
        if (!$alg) {
            return '';
        }
        $jwt->verify($alg, $key);
        $claims = $jwt->getClaims();
        return $claims[self::CLAIM];
    }

    /**
     * Writes the session data to a cookie containing a signed JWT
     *
     * @param session_id (unused)
     * @param session_data the serialized session data
     * @return bool true if the cookie header was set
     * @throws OverflowException if there is too much session data
     * @throws JWTException if the data cannot be signed
     */
    public function write($session_id, $session_data) {
        list($alg, $key, $keyID) = $this->getSecret();
        $data = [
            'jti' => $session_id,
//            future considerations:
//            'nbf' => not before,
//            'exp' => expires,
            self::CLAIM => $session_data,
        ];
        $jwt = (new JWT($data))
            ->setAlgorithm($alg)
            ->setKeyID($keyID);
        $data = $jwt->encode($key);
        if (strlen($data) >= 4096) {
            throw new OverflowException(
                "Too much data in session to use JWT driver");
        }
        $params = session_get_cookie_params();
        ($this->writer)($this->cookie,
            $data,
            $params['lifetime'],
            $params['path'],
            $params['domain'],
            $params['secure'],
            $params['httponly']);
        return true;
    }

    /**
     * Gets the encryption info for the given key ID, defaulting to the most
     * recent ID
     *
     * @return array algorithm, secret, key id
     */
    private function getSecret($keyId = null) {
        // If a key ID is not specified (i.e. on write), use the most recent
        // one
        if (null === $keyId) {
            end($this->secrets);
            $keyId = key($this->secrets);
        }
        if (!array_key_exists($keyId, $this->secrets)) {
            return [null,null,null];
        }
        $data = $this->secrets[$keyId];
        return [$data['alg'], $data['secret'], $keyId];
    }

    /**
     * This exists pretty much entirely to test that `setcookie` is called when
     * and how it should be; there's no reason to call this during normal use.
     *
     * @codeCoverageIgnoreStart
     */
    public function setWriter(callable $writer) {
        $this->writer = $writer;
        return $this;
    }
    // @codeCoverageIgnoreEnd
}
