<?php

namespace Firehed\JWT;

use InvalidArgumentException;
use OverflowException;


/**
 * @coversDefaultClass Firehed\JWT\SessionHandler
 * @covers ::<protected>
 * @covers ::<private>
 */
class SessionHandlerTest extends \PHPUnit_Framework_TestCase
{

    public function setUp() {
        $this->handler = new SessionHandler([
            1 => [
                'alg' => Algorithm::HMAC_SHA_256(),
                'secret' => 't0p $3cr37',
            ]
        ]);
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
     * @covers ::__construct
     * @dataProvider badSecrets
     */
    public function testBadSecrets(array $secrets) {
        $this->expectException(InvalidArgumentException::class);
        new SessionHandler($secrets);
    }

    /**
     * @covers ::read
     */
    public function testRead() {
        $_COOKIE['jwt_sid'] = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6MX0'.
            '.eyJqdGkiOiJYaldsX2ciLCJzZCI6Inh8aToxNDU2NzAzMTg2OyJ9.Y9gokU2iYi7'.
            'Kt46G3_L0LKfJyHbFz1aJGJoXGql2dJE';
        $expected = 'x|i:1456703186;';
        $data = $this->handler->read('session_id');
        $this->assertSame($expected, $data,
            'JWT cookie did not decode as expected');
    }

    /**
     * @covers ::read
     */
    public function testReadWithUnexpectedKeyID() {
        $_COOKIE['jwt_sid'] = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Mn0'.
            '.eyJqdGkiOiJYaldsX2ciLCJzZCI6Inh8aToxNDU2NzAzMTg2OyJ9.fy0iwbVX0VZ'.
            'Uw7VI68BucHJiEB8Mnhx-bVlAUYssLrg';
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
        $jwt = JWT::decode($this->cookieData);
        $jwt->verify(Algorithm::HMAC_SHA_256(), 't0p $3cr37');

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

    // -( DataProviders )------------------------------------------------------

    public function badSecrets() {
        return [
            [[1 => []]],
            [[1 => [
                'secret' => 3,
                'alg' => Algorithm::HMAC_SHA_256(),
            ]]],
            [[1 => [
                'secret' => 'good secret',
                'alg' => 'sha256',
            ]]],
            [[1 => [
                'secret' => 'good secret',
                'alg' => Algorithm::NONE(),
            ]]],
            [[
                1 => [
                    'secret' => 'good secret',
                    'alg' => Algorithm::HMAC_SHA_256(),
                ],
                2 => [
                    'secret' => 'good secret',
                    'alg' => Algorithm::NONE(),
                ]
            ]],

        ];
    }

    private $cookieData = '';
    public function setCookie(...$args) {
        $this->cookieData = $args[1];
    }
}
