<?php

namespace Firehed\JWT;

use InvalidArgumentException;
use OverflowException;
use Firehed\Security\Secret;


/**
 * @coversDefaultClass Firehed\JWT\SessionHandler
 * @covers ::<protected>
 * @covers ::<private>
 */
class SessionHandlerTest extends \PHPUnit\Framework\TestCase
{

    /**
     * Stores the data that would have gone to `setcookie`
     */
    private $cookieData = '';
    private $container;

    public function setUp() {
        $this->container = (new KeyContainer())
            ->addKey(1, Algorithm::HMAC_SHA_256(), new Secret('t0p $3cr37'));
        $this->handler = new SessionHandler($this->container);
        $this->handler->setWriter([$this,'setCookie']);
    }

    /**
     * @covers ::open
     */
    public function testOpen() {
        $this->assertTrue($this->handler->open('', ''));
    }

    /**
     * @covers ::close
     */
    public function testClose() {
        $this->assertTrue($this->handler->close());
    }

    /**
     * @covers ::gc
     */
    public function testGC() {
        $this->assertTrue($this->handler->gc(1));
    }

    /**
     * @covers ::destroy
     */
    public function testDestroy() {
        $this->assertTrue($this->handler->destroy('session_id'));
    }

    /**
     * @covers ::read
     */
    public function testRead() {
        $_COOKIE[SessionHandler::DEFAULT_COOKIE] = 'eyJhbGciOiJIUzI1NiIsInR5cC'.
            'I6IkpXVCIsImtpZCI6MX0.eyJqdGkiOiJYaldsX2ciLCJzZCI6Inh8aToxNDU2NzA'.
            'zMTg2OyJ9.Y9gokU2iYi7Kt46G3_L0LKfJyHbFz1aJGJoXGql2dJE';
        $expected = 'x|i:1456703186;';
        $data = $this->handler->read('session_id');
        $this->assertSame($expected, $data,
            'JWT cookie did not decode as expected');
    }

    /**
     * @covers ::read
     */
    public function testReadWithForgedSignature() {
        $_COOKIE[SessionHandler::DEFAULT_COOKIE] = 'eyJhbGciOiJIUzI1NiIsInR5cC'.
            'I6IkpXVCIsImtpZCI6MX0.eyJqdGkiOiJYaldsX2ciLCJzZCI6Inh8aToxNDU2NzA'.
            'zMTg2OyJ9.invalidsig';
        $data = $this->handler->read('');
        $this->assertSame('', $data,
            'Cookie with invalid signature should return no data when read');
    }

    /**
     * @covers ::read
     */
    public function testReadWithUnexpectedKeyID() {
        $_COOKIE[SessionHandler::DEFAULT_COOKIE] = 'eyJhbGciOiJIUzI1NiIsInR5cC'.
            'I6IkpXVCIsImtpZCI6Mn0.eyJqdGkiOiJYaldsX2ciLCJzZCI6Inh8aToxNDU2NzA'.
            'zMTg2OyJ9.fy0iwbVX0VZUw7VI68BucHJiEB8Mnhx-bVlAUYssLrg';
        $data = $this->handler->read('session_id');
        $this->assertSame('', $data,
            'JWT with unknown key ID should return an empty string');
    }

    /**
     * @covers ::read
     */
    public function testReadWithEmptyCookie() {
        $this->assertEmpty($_COOKIE, 'Precondition failed: COOKIE not empty');
        $data = $this->handler->read('session_id');
        $this->assertSame('', $data,
            'JWT with unknown key ID should return an empty string');
    }

    /**
     * @covers ::write
     */
    public function testWrite() {
        $this->handler->write('sid', 'somedata');
        $jwt = JWT::fromEncoded($this->cookieData, $this->container);

        $claims = $jwt->getClaims();
        $this->assertSame('somedata', $claims[SessionHandler::CLAIM],
            'Claims were not written to the cookie');
    }

    /**
     * @covers ::write
     */
    public function testWriteTooMuchThrows() {
        $this->expectException(OverflowException::class);
        $this->handler->write('sid', str_repeat('asdf', 1024));
    }

    // -( Helpers )------------------------------------------------------------

    /**
     * Injected replacement callback for direct `setCookie` function
     */
    public function setCookie(...$args) {
        $this->cookieData = $args[1];
    }
}
