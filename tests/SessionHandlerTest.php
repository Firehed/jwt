<?php

namespace Firehed\JWT;

use Firehed\Security\Secret;
use InvalidArgumentException;
use OverflowException;
use SessionHandlerInterface;

/**
 * @coversDefaultClass Firehed\JWT\SessionHandler
 * @covers ::<protected>
 * @covers ::<private>
 */
class SessionHandlerTest extends \PHPUnit\Framework\TestCase
{

    /**
     * Stores the data that would have gone to `setcookie`
     * @var string
     */
    private $cookieData = '';

    /** @var KeyContainer */
    private $container;

    /** @var SessionHandlerInterface */
    private $handler;

    /**
     */
    public function setUp(): void
    {
        $this->container = (new KeyContainer())
            ->addKey(1, Algorithm::HMAC_SHA_256, new Secret('t0p $3cr37'));
        $this->handler = new SessionHandler($this->container);
        $this->handler->setWriter([$this, 'setCookie']);
    }

    /**
     * @covers ::open
     */
    public function testOpen(): void
    {
        self::assertTrue($this->handler->open('', ''));
    }

    /**
     * @covers ::close
     */
    public function testClose(): void
    {
        self::assertTrue($this->handler->close());
    }

    /**
     * @covers ::gc
     */
    public function testGC(): void
    {
        self::assertTrue($this->handler->gc(1));
    }

    /**
     * @covers ::destroy
     */
    public function testDestroy(): void
    {
        self::assertTrue($this->handler->destroy('session_id'));
    }

    /**
     * @covers ::read
     */
    public function testRead(): void
    {
        $_COOKIE[SessionHandler::DEFAULT_COOKIE] = 'eyJhbGciOiJIUzI1NiIsInR5cC'.
            'I6IkpXVCIsImtpZCI6MX0.eyJqdGkiOiJYaldsX2ciLCJzZCI6Inh8aToxNDU2NzA'.
            'zMTg2OyJ9.Y9gokU2iYi7Kt46G3_L0LKfJyHbFz1aJGJoXGql2dJE';
        $expected = 'x|i:1456703186;';
        $data = $this->handler->read('session_id');
        self::assertSame(
            $expected,
            $data,
            'JWT cookie did not decode as expected'
        );
    }

    /**
     * @covers ::read
     */
    public function testReadWithForgedSignature(): void
    {
        $_COOKIE[SessionHandler::DEFAULT_COOKIE] = 'eyJhbGciOiJIUzI1NiIsInR5cC'.
            'I6IkpXVCIsImtpZCI6MX0.eyJqdGkiOiJYaldsX2ciLCJzZCI6Inh8aToxNDU2NzA'.
            'zMTg2OyJ9.invalidsig';
        $data = $this->handler->read('');
        self::assertSame(
            '',
            $data,
            'Cookie with invalid signature should return no data when read'
        );
    }

    /**
     * @covers ::read
     */
    public function testReadWithUnexpectedKeyID(): void
    {
        $_COOKIE[SessionHandler::DEFAULT_COOKIE] = 'eyJhbGciOiJIUzI1NiIsInR5cC'.
            'I6IkpXVCIsImtpZCI6Mn0.eyJqdGkiOiJYaldsX2ciLCJzZCI6Inh8aToxNDU2NzA'.
            'zMTg2OyJ9.fy0iwbVX0VZUw7VI68BucHJiEB8Mnhx-bVlAUYssLrg';
        $data = $this->handler->read('session_id');
        self::assertSame(
            '',
            $data,
            'JWT with unknown key ID should return an empty string'
        );
    }

    /**
     * @covers ::read
     */
    public function testReadWithEmptyCookie(): void
    {
        self::assertEmpty($_COOKIE, 'Precondition failed: COOKIE not empty');
        $data = $this->handler->read('session_id');
        self::assertSame(
            '',
            $data,
            'JWT with unknown key ID should return an empty string'
        );
    }

    /**
     * @covers ::write
     */
    public function testWrite(): void
    {
        $this->handler->write('sid', 'somedata');
        $jwt = JWT::fromEncoded($this->cookieData, $this->container);

        $claims = $jwt->getClaims();
        self::assertSame(
            'somedata',
            $claims[SessionHandler::CLAIM],
            'Claims were not written to the cookie'
        );
    }

    /**
     * @covers ::write
     */
    public function testWriteTooMuchThrows(): void
    {
        $this->expectException(OverflowException::class);
        $this->handler->write('sid', str_repeat('asdf', 1024));
    }

    // -( Helpers )------------------------------------------------------------

    /**
     * Injected replacement callback for direct `setCookie` function
     */
    public function setCookie(
        string $name,
        string $value = '',
        int $expires = 0,
        string $path = '',
        string $domain = '',
        bool $secure = false,
        bool $httponly = false
    ): bool {
        $this->cookieData = $value;
        return true;
    }
}
