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
    public function testDecode($vector, Algorithm $algorithm, $exp_claims, $secret) {
        $JWT = JWT::decode($vector, $secret);
        $this->assertInstanceOf('Firehed\JWT\JWT', $JWT);
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
    public function testEncode($vector, Algorithm $algorithm, $claims, $secret) {
        $tok = new JWT($claims);
        $tok->setAlgorithm($algorithm);
        $out = $tok->encode($secret);
        $this->assertSame($vector, $out, 'Output did not match test vector');
    } // testEncode

    /**
     * @expectedException Firehed\JWT\TokenNotYetValidException
     */
    public function testEnforceNBF() {
        JWT::decode('eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJuYmYiOjk5OTk5OTk5OTk5OX0.');
    } // testEnforceNBF

    /**
     * @expectedException Firehed\JWT\TokenExpiredException
     */
    public function testEnforceEXP() {
        JWT::decode('eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJleHAiOjF9.');
    } // testEnforceEXP

    /**
     * @covers ::isSigned
     * @dataProvider vectors
     */
    public function testIsSigned($token, Algorithm $algorithm, $claims, $secret, $shouldBeSigned) {
        $tok = JWT::decode($token, $secret);
        if ($shouldBeSigned) {
            $this->assertTrue($tok->isSigned(), 'isSigned should return TRUE');
        }
        else {
            $this->assertFalse($tok->isSigned(), 'isSigned should return FALSE');
        }
    } // testIsSigned

    /**
     * @covers ::encode
     * @expectedException Firehed\JWT\JWTException
     */
    public function testNotSettingAlgorithmFails() {
        $tok = new JWT([], ['data' => true]);
        $tok->encode('test key');
    } // testNotSettingAlgorithmFails

    /**
     * @covers ::decode
     * @expectedException Firehed\JWT\InvalidFormatException
     */
    public function testDecodeStringWithNoPeriods() {
        JWT::decode('asdfklj290iasdf');
    } // testDecodeStringWithNoPeriods

    /**
     * @covers ::decode
     * @expectedException Firehed\JWT\InvalidFormatException
     */
    public function testDecodeInvalidJSON() {
        // test.test
        JWT::decode('dGVzdA.dGVzdA.');
    } // testDecodeInvalidJSON

    /**
     * @covers ::encode
     * @expectedException Firehed\JWT\JWTException
     */
    public function testExplicitlySettingAlgorithmIsRequired() {
        $jwt = new JWT(['foo' => 'bar']);
        $jwt->encode('secret');
    } // testExplicitlySettingAlgorithmIsRequired

    /**
     * @covers ::setAlgorithm
     */
    public function testSetAlgorithmIsChainable() {
        $jwt = new JWT(['foo' => 'bar']);
        $this->assertSame($jwt, $jwt->setAlgorithm(Algorithm::NONE()),
            'setAlgorithm should return $this');
    } // testSetAlgorithmIsChainable

    /**
     * @covers ::__construct
     */
    public function testConstruct() {
        $jwt = new JWT(['foo' => 'bar']);
        $this->assertInstanceOf('Firehed\JWT\JWT', $jwt, 'Construct failed');
    } // testConstruct

    public function vectors() {
        return [
            [
                'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Njc4OTAs'.
                'Im5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ.eoaDVGTClRdfxUZXiP'.
                's3f8FmJDkDE_VCQFXqKxpLsts',
                Algorithm::HMAC_SHA_256(),
                ['sub' => 1234567890, 'name' => 'John Doe', 'admin' => true,],
                'secret',
                true,
            ],
            [
                'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOjEyMzQ1Njc4OTAsI'.
                'm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ.',
                Algorithm::NONE(),
                ['sub' => 1234567890, 'name' => 'John Doe', 'admin' => true,],
                '',
                false,
            ],
            [
                'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Njc4OTAsI'.
                'm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ.fSCfxDB4cFVvzd6IqiNT'.
                'uItTYiv-tAp5u5XplJWRDBGNF1rgGn1gyYK9LuHobWWpwqCzI7pEHDlyrbNHaQ'.
                'Jmqg',
                Algorithm::HMAC_SHA_512(),
                ['sub' => 1234567890, 'name' => 'John Doe', 'admin' => true,],
                'secret',
                true,
            ],
        ];
    } // vectors

}
