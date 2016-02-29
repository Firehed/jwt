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
     * @covers ::getClaims
     * @dataProvider vectors
     * */
    public function testDecode($vector, Algorithm $algorithm, $exp_claims, $secret) {
        $JWT = JWT::decode($vector, $algorithm, $secret);
        $this->assertInstanceOf('Firehed\JWT\JWT', $JWT);
        $this->assertSame($exp_claims, $JWT->getUnverifiedClaims(),
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
        $JWT = JWT::decode($vector, Algorithm::HMAC_SHA_256(), $secret);
    } // testDecodeThrowsWithBadSignature

    /**
     * @covers ::getUnverifiedClaims
     */
    public function testDecodeAllowsInvalidSignatureWhenExplicitlyConfigured() {
        $vector = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Njc4OT'.
            'AsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ.thisisnotvalid';
        $JWT = JWT::decode($vector);
        $expected = [
            "sub" => 1234567890,
            "name" => "John Doe",
            "admin" => true
        ];
        $this->assertSame($expected, $JWT->getUnverifiedClaims());
    } // testDecodeAllowsInvalidSignatureWhenExplicitlyConfigured

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
        JWT::decode('eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.'.
            'eyJuYmYiOjk5OTk5OTk5OTk5OX0.');
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
        $tok = JWT::decode($token, $algorithm, $secret);
        if ($shouldBeSigned) {
            $this->assertTrue($tok->isSigned(), 'isSigned should return TRUE');
        }
        else {
            $this->assertFalse($tok->isSigned(), 'isSigned should return FALSE');
        }
    } // testIsSigned

    /**
     * @covers ::setKeyID
     */
    public function testSetKeyIDProducesCorrectOutput() {
        $expected = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6M30.eyJ1c2VyI'.
            'joiRm9vIEJhciJ9.E2gekVU0lErEsIqIWSdG7-32yVhALHr_tZu5DFfWVjM';
        $jwt = new JWT(['user' => 'Foo Bar']);
        $jwt->setKeyId(3)
            ->setAlgorithm(Algorithm::HMAC_SHA_256());
        $this->assertSame($expected, $jwt->encode('secret'),
            'Encoded output did not match expected');
    }

    /**
     * @covers ::getKeyID
     */
    public function testGetKeyIDFromDecodedInput() {
        $data = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6M30.eyJ1c2VyIjoiR'.
            'm9vIEJhciJ9.E2gekVU0lErEsIqIWSdG7-32yVhALHr_tZu5DFfWVjM';
        $jwt = JWT::decode($data);
        $this->assertSame(3, $jwt->getKeyID(),
            '`kid` header was not retreived correctly');
        // use key id 3 to determine secret
        $jwt->verify(Algorithm::HMAC_SHA_256(), 'secret');
        $this->assertSame(['user' => 'Foo Bar'], $jwt->getClaims(),
            'getClaims was wrong after checking key id');


    }

    /**
     * @covers ::encode
     * @expectedException Firehed\JWT\JWTException
     */
    public function testNotSettingAlgorithmFails() {
        $tok = new JWT(['data' => true]);
        $tok->encode('test key');
    } // testNotSettingAlgorithmFails

    /**
     * @covers ::__construct
     * @covers ::getClaims
     */
    public function testNewTokenAllowsAccessToClaims() {
        $data = ['data' => true];
        $tok = new JWT($data);
        $this->assertEquals($data, $tok->getClaims(),
            'getClaims did not return the provided data');
    } // testNewTokenAllowsAccessToClaims

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
     * @covers ::getClaims
     * @expectedException BadMethodCallException
     */
    public function testNoneAlgorithmRequiresGetUnverifedClaims() {
        $vector = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJmb28iOiJiYXIifQ.';
        $jwt = JWT::decode($vector);
        $jwt->getClaims();
    } // testNoneAlgorithmRequiresGetUnverifedClaims

    /**
     * @covers ::getClaims
     * @covers ::verify
     * @expectedException BadMethodCallException
     */
    public function testNoneAlgorithmCannotVerifyClaims() {
        $vector = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJmb28iOiJiYXIifQ.';
        $jwt = JWT::decode($vector);
        $jwt->verify(Algorithm::NONE(), '');
        $jwt->getClaims();
    }

    /**
     * @covers ::getUnverifiedClaims
     */
    public function testNoneAlgorithmWorksWithUnverifedClaims() {
        $vector = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.'.
            'eyJmb28iOiJiYXIifQ.';
        $JWT = JWT::decode($vector);
        $claims = $JWT->getUnverifiedClaims();
        $this->assertSame(["foo" => "bar"], $claims,
            "Claims were not decoded correctly");
    } // testNoneAlgorithmWorksWithUnverifedClaims

    /**
     * @covers ::verify
     * @covers ::getClaims
     * @covers ::decode
     */
    public function testVerifyAfterDecode() {
        $vector = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'.
            'eyJ1aWQiOiJzZWNyZXQifQ.'.
            'LOf2KSz1soy8F7JpYrp85QwhcGSIt1sBCc91iFU1JuQ';
        $JWT = JWT::decode($vector);
        // The claims in the vector provide the secret. This is to simulate the
        // situation where a value in the claim would be used to look up the
        // secret used to sign it, e.g. per-user signatures.
        $secret = $JWT->getUnverifiedClaims()['uid'];
        $JWT->verify(Algorithm::HMAC_SHA_256(), $secret);
        $claims = $JWT->getClaims();
        $this->assertEquals(['uid' => 'secret'], $claims);
    } // testVerifyAfterDecode

    /**
     * @covers ::verify
     * @expectedException Firehed\JWT\InvalidSignatureException
     */
    public function testVerifyThrowsWhenInitialDecodeWasNotVerified() {
        $vector = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'.
            'eyJ1aWQiOiJzZWNyZXQifQ.'.
            'thisisnotvalid';
        $JWT = JWT::decode($vector);
        // The claims in the vector provide the secret. This is to simulate the
        // situation where a value in the claim would be used to look up the
        // secret used to sign it, e.g. per-user signatures.
        $secret = $JWT->getUnverifiedClaims()['uid'];
        $JWT->verify(Algorithm::HMAC_SHA_256(), $secret);
    }

    /**
     * @covers ::verify
     * @expectedException Firehed\JWT\InvalidSignatureException
     */
    public function testModifiedAlgorithmTriggersInvalidSignature() {
        $vector = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'.
            'eyJmb28iOiJiYXIifQ.'.
            'dtxWM6MIcgoeMgH87tGvsNDY6cHWL6MGW4LeYvnm1JA';
        // Assume the server is hardcoded to HMAC-SHA-512 or the same was
        // dervied from the key id. The provided, tampered-with token is signed
        // with HS256, although the secret is actually valid (indicitave of the
        // RSxxx swap
        JWT::decode($vector, Algorithm::HMAC_SHA_512(), 'secret');
    } // testModifiedAlgorithmTriggersInvalidSignature

    /**
     * @covers ::__construct
     */
    public function testConstruct() {
        $jwt = new JWT(['foo' => 'bar']);
        $this->assertInstanceOf('Firehed\JWT\JWT', $jwt, 'Construct failed');
    } // testConstruct

    public function vectors() {
        // [
        //  encoded JWT,
        //  algorithm,
        //  claims,
        //  key,
        //  should be signed
        // ]
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
                'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Njc4OTAsI'.
                'm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ.fSCfxDB4cFVvzd6IqiNT'.
                'uItTYiv-tAp5u5XplJWRDBGNF1rgGn1gyYK9LuHobWWpwqCzI7pEHDlyrbNHaQ'.
                'Jmqg',
                Algorithm::HMAC_SHA_512(),
                ['sub' => 1234567890, 'name' => 'John Doe', 'admin' => true,],
                'secret',
                true,
            ],
            [
                'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1cmwiOiJodHRwOi8vZXhhb'.
                'XBsZS5jb20ifQ.yEJmrAmC_Tr_lVOV5C0yAyK__omFr9J8BM_nulPpGOA',
                Algorithm::HMAC_SHA_256(),
                ['url' => 'http://example.com'],
                'secret',
                true,
            ],
            [
                'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1cmwiOiJodHRwOi8vZXhhbX'.
                'BsZS5jb20ifQ.',
                Algorithm::NONE(),
                ['url' => 'http://example.com'],
                '',
                false,
            ],
        ];
    } // vectors

}
