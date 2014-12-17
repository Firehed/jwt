<?php

namespace Firehed\JWT;

/**
 * @coversDefaultClass Firehed\JWT\JWT
 * @covers ::<protected>
 * @covers ::<private>
 */
class JWTTest extends \PHPUnit_Framework_TestCase {

    /**
     * @covers ::decode
     * @dataProvider vectors
     * */
    public function testDecode($vector, $exp_headers, $exp_claims, $secret) {
        $JWT = JWT::decode($vector, $secret);
        $this->assertInstanceOf('Firehed\JWT\JWT', $JWT);
        $this->assertSame($exp_headers, $JWT->getHeaders(),
            'Headers did not match');
        $this->assertSame($exp_claims, $JWT->getClaims(),
            'Claims did not match');
    } // testDecode

    /**
     * @covers ::decode
     * @expectedException Firehed\JWT\InvalidSignatureException
     */
    public function testDecodeThrowsWithBadSignature() {
        $vector = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Njc4OT'.
            'AsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ.thisisnotvalid';
        $secret = 'secret';
        $JWT = JWT::decode($vector, $secret);
    } // testDecodeThrowsWithBadSignature

    /**
     * @covers ::encode
     * @dataProvider vectors
     */
    public function testEncode($vector, $headers, $claims, $secret) {
        $tok = new JWT($headers, $claims);
        $out = $tok->encode($secret);
        $this->assertSame($vector, $out, 'Output did not match test vector');
    } // testEncode

    /**
     * @expectedException Firehed\JWT\TokenNotYetValidException
     */
    public function testEnforceNBF() {
        JWT::decode('eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJuYmYiOjk5OTk5OTk5OTk5OX0.');
    }
    /**
     * @expectedException Firehed\JWT\TokenExpiredException
     */
    public function testEnforceEXP() {
        JWT::decode('eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJleHAiOjF9.');
    }

    public function vectors() {
        return [
            [
                'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Njc4OTAs'.
                'Im5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ.eoaDVGTClRdfxUZXiP'.
                's3f8FmJDkDE_VCQFXqKxpLsts',
                ['alg' => 'HS256', 'typ' => 'JWT',],
                ['sub' => 1234567890, 'name' => 'John Doe', 'admin' => true,],
                'secret',
            ],
            [
                'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOjEyMzQ1Njc4OTAsI'.
                'm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ.',
                ['alg' => 'none', 'typ' => 'JWT',],
                ['sub' => 1234567890, 'name' => 'John Doe', 'admin' => true,],
                '',
            ],
            [
                'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Njc4OTAsI'.
                'm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ.fSCfxDB4cFVvzd6IqiNT'.
                'uItTYiv-tAp5u5XplJWRDBGNF1rgGn1gyYK9LuHobWWpwqCzI7pEHDlyrbNHaQ'.
                'Jmqg',
                ['alg' => 'HS512', 'typ' => 'JWT',],
                ['sub' => 1234567890, 'name' => 'John Doe', 'admin' => true,],
                'secret',
            ],
        ];
    } // vectors
}
