<?php

namespace Firehed\JWT;

use InvalidArgumentException;
use OverflowException;
use SessionHandlerInterface;

class SessionHandler implements SessionHandlerInterface
{

    const CLAIM = 'sd';
    const DEFAULT_COOKIE = 'jwt_sid';

    /** @var string */
    private $cookie = self::DEFAULT_COOKIE;

    /** @var KeyContainer */
    private $secrets;

    /** @var callable */
    private $writer = 'setcookie';

    /**
     * Provide an array of key IDs and their associated algorithms and secrets
     *
     * Note that Algorithm::NONE is explicitly blocked, since this would
     * produce an unsigned JWT allowing users to modify their own session data.
     */
    public function __construct(KeyContainer $secrets)
    {
        $this->secrets = $secrets;
    }

    /**
     * No-op, interface adherence only
     * @return bool true, always
     */
    public function close()
    {
        return true;
    }

    /**
     * @param string $session_id
     * @return bool
     */
    public function destroy($session_id)
    {
        ($this->writer)($this->cookie, '', time()-86400); // Expire yesterday
        return true;
    }

    /**
     * No-op, interface adherence only
     * @param int $maxlifetime
     * @return bool true, always
     */
    public function gc($maxlifetime)
    {
        return true;
    }

    /**
     * No-op, interface adherence only
     * @param string $save_path
     * @param string $name
     * @return bool true, always
     */
    public function open($save_path, $name)
    {
        return true;
    }

    /**
     * Reads the session data from the cookie, verifies its authenticity, and
     * returns the data to be natively unserialized into the $_SESSION
     * superglobal
     *
     * @param string $session_id (unused)
     * @return string the serialized session string
     * @throws JWTException if JWT processing fails, tampering is detected, etc
     */
    public function read($session_id)
    {
        // session_id is intentionally ignored
        if (!array_key_exists($this->cookie, $_COOKIE)) {
            return '';
        }
        $encoded = $_COOKIE[$this->cookie];
        try {
            $jwt = JWT::fromEncoded($encoded, $this->secrets);
            $claims = $jwt->getClaims();
            return $claims[self::CLAIM];
        } catch (KeyNotFoundException $e) {
            return '';
        } catch (InvalidSignatureException $e) {
            return '';
        }
    }

    /**
     * Writes the session data to a cookie containing a signed JWT
     *
     * @param string $session_id (unused)
     * @param string $session_data the serialized session data
     * @return bool true if the cookie header was set
     * @throws OverflowException if there is too much session data
     * @throws JWTException if the data cannot be signed
     */
    public function write($session_id, $session_data)
    {
        $data = [
            'jti' => $session_id,
//            future considerations:
//            'nbf' => not before,
//            'exp' => expires,
            self::CLAIM => $session_data,
        ];
        $jwt = (new JWT($data))
            ->setKeys($this->secrets);
        $data = $jwt->getEncoded();
        if (strlen($data) >= 4096) {
            throw new OverflowException(
                "Too much data in session to use JWT driver"
            );
        }
        $params = session_get_cookie_params();
        ($this->writer)(
            $this->cookie,
            $data,
            $params['lifetime'],
            $params['path'],
            $params['domain'],
            $params['secure'],
            $params['httponly']
        );
        return true;
    }

    /**
     * This exists pretty much entirely to test that `setcookie` is called when
     * and how it should be; there's no reason to call this during normal use.
     *
     * @internal
     * @return $this
     * @codeCoverageIgnoreStart
     */
    public function setWriter(callable $writer)
    {
        $this->writer = $writer;
        return $this;
    }
    // @codeCoverageIgnoreEnd
}
