<?php

namespace Firehed\JWT;

use Firehed\Security\Secret;
use BadMethodCallException;

/**
 * @coversDefaultClass Firehed\JWT\JWT
 * @covers ::<protected>
 * @covers ::<private>
 */
class JWTTest extends \PHPUnit\Framework\TestCase
{

    /**
     * @covers ::fromEncoded
     * @covers ::getClaims
     * @dataProvider vectors
     * */
    public function testDecode(string $vector, array $exp_claims, KeyContainer $keys)
    {
        $JWT = JWT::fromEncoded($vector, $keys);
        $this->assertInstanceOf('Firehed\JWT\JWT', $JWT);
        $this->assertSame(
            $exp_claims,
            $JWT->getUnverifiedClaims(),
            'Claims did not match'
        );
    } // testDecode

    /**
     * @covers ::getClaims
     */
    public function testGetClaimsThrowsWithBadSignature()
    {
        $vector = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Njc4OT'.
            'AsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ.thisisnotvalid';
        $jwt = JWT::fromEncoded($vector, $this->getKeyContainer());
        $this->expectException(InvalidSignatureException::class);
        $jwt->getClaims();
    } // testGetClaimsThrowsWithBadSignature

    /**
     * @covers ::getUnverifiedClaims
     */
    public function testDecodeAllowsInvalidSignatureWhenExplicitlyConfigured()
    {
        $vector = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Njc4OT'.
            'AsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ.thisisnotvalid';
        $JWT = JWT::fromEncoded(
            $vector,
            $this->getKeyContainer()->setDefaultKey('none')
        );
        $expected = [
            "sub" => 1234567890,
            "name" => "John Doe",
            "admin" => true
        ];
        $this->assertSame($expected, $JWT->getUnverifiedClaims());
    } // testDecodeAllowsInvalidSignatureWhenExplicitlyConfigured

    /**
     * @covers ::getEncoded
     * @dataProvider vectors
     */
    public function testEncode(string $vector, array $claims, KeyContainer $keys)
    {
        $tok = new JWT($claims);
        $tok->setKeys($keys);
        $out = $tok->getEncoded();
        $this->assertSame($vector, $out, 'Output did not match test vector');
    } // testEncode

    /**
     * @expectedException Firehed\JWT\TokenNotYetValidException
     */
    public function testEnforceNBF()
    {
        JWT::fromEncoded(
            'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.'.
            'eyJuYmYiOjk5OTk5OTk5OTk5OX0.',
            $this->getKeyContainer()->setDefaultKey('none')
        );
    } // testEnforceNBF

    /**
     * @expectedException Firehed\JWT\TokenExpiredException
     */
    public function testEnforceEXP()
    {
        JWT::fromEncoded(
            'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJleHAiOjF9.',
            $this->getKeyContainer()->setDefaultKey('none')
        );
    } // testEnforceEXP

    /**
     * @covers ::getEncoded
     */
    public function testSpecifyingEncodingKeyProducesCorrectOutput()
    {
        $expected = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6M30.eyJ1c2VyI'.
            'joiRm9vIEJhciJ9.E2gekVU0lErEsIqIWSdG7-32yVhALHr_tZu5DFfWVjM';
        $keys = (new KeyContainer())
            ->addKey(3, Algorithm::HMAC_SHA_256(), new Secret('secret'))
            ->addKey(1, Algorithm::HMAC_SHA_384(), new Secret('xxx'))
            ->addKey(2, Algorithm::HMAC_SHA_512(), new Secret('yyy'));
        $jwt = new JWT(['user' => 'Foo Bar']);
        $jwt->setKeys($keys);
        $this->assertSame(
            $expected,
            $jwt->getEncoded(3),
            'Encoded output did not match expected'
        );
    }

    /**
     * Ensures that the key ID header value takes precedence when multiple keys
     * are made available to the decoding method, and the data remains correct.
     * @covers ::getKeyID
     */
    public function testGetKeyIDFromDecodedInput()
    {
        $data = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6M30.eyJ1c2VyIjoiR'.
            'm9vIEJhciJ9.E2gekVU0lErEsIqIWSdG7-32yVhALHr_tZu5DFfWVjM';
        $kc = (new KeyContainer())
            ->addKey(2, Algorithm::HMAC_SHA_384(), new Secret('xxx'))
            ->addKey(3, Algorithm::HMAC_SHA_256(), new Secret('secret'))
            ->addKey(4, Algorithm::HMAC_SHA_512(), new Secret('yyy'))
            ->setDefaultKey(2);
        $jwt = JWT::fromEncoded($data, $kc);
        $this->assertSame(
            3,
            $jwt->getKeyID(),
            '`kid` header was not retreived correctly'
        );
        // use key id 3 to determine secret
        $this->assertSame(
            ['user' => 'Foo Bar'],
            $jwt->getClaims(),
            'getClaims was wrong after checking key id'
        );
    }

    /**
     * @covers ::getEncoded
     */
    public function testNotSettingKeysFails()
    {
        $tok = new JWT(['data' => true]);
        $this->expectException(BadMethodCallException::class);
        $tok->getEncoded();
    } // testNotSettingAlgorithmFails

    /**
     * @covers ::__construct
     * @covers ::getClaims
     */
    public function testNewTokenAllowsAccessToClaims()
    {
        $data = ['data' => true];
        $tok = new JWT($data);
        $this->assertEquals(
            $data,
            $tok->getClaims(),
            'getClaims did not return the provided data'
        );
    } // testNewTokenAllowsAccessToClaims

    /**
     * @covers ::fromEncoded
     * @expectedException Firehed\JWT\InvalidFormatException
     */
    public function testDecodeStringWithNoPeriods()
    {
        JWT::fromEncoded('asdfklj290iasdf', $this->getKeyContainer());
    } // testDecodeStringWithNoPeriods

    /**
     * @covers ::fromEncoded
     * @expectedException Firehed\JWT\InvalidFormatException
     */
    public function testDecodeInvalidJSON()
    {
        // test.test
        JWT::fromEncoded('dGVzdA.dGVzdA.', $this->getKeyContainer());
    } // testDecodeInvalidJSON

    /**
     * @covers ::getClaims
     * @expectedException BadMethodCallException
     */
    public function testNoneAlgorithmRequiresGetUnverifedClaims()
    {
        $vector = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJmb28iOiJiYXIifQ.';
        $jwt = JWT::fromEncoded(
            $vector,
            $this->getKeyContainer()->setDefaultKey('none')
        );
        $jwt->getClaims();
    } // testNoneAlgorithmRequiresGetUnverifedClaims

    /**
     * @covers ::getClaims
     */
    public function testModifiedAlgorithmTriggersInvalidSignature()
    {
        $vector = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'.
            'eyJmb28iOiJiYXIifQ.'.
            'dtxWM6MIcgoeMgH87tGvsNDY6cHWL6MGW4LeYvnm1JA';
        // Assume the server is hardcoded to HMAC-SHA-512 or the same was
        // dervied from the key id. The provided, tampered-with token is signed
        // with HS256, although the secret is actually valid (indicitave of the
        // RSxxx swap
        $keys = $this->getKeyContainer()
            ->setDefaultKey('HS512');
        $jwt = JWT::fromEncoded($vector, $keys);
        $this->expectException(InvalidSignatureException::class);
        $jwt->getClaims();
    } // testModifiedAlgorithmTriggersInvalidSignature

    /**
     * @covers ::__construct
     */
    public function testConstruct()
    {
        $jwt = new JWT(['foo' => 'bar']);
        $this->assertInstanceOf('Firehed\JWT\JWT', $jwt, 'Construct failed');
    } // testConstruct

    /**
     * @covers ::setKeys
     */
    public function testSetKeysReturnsthis()
    {
        $jwt = new JWT([]);
        $this->assertSame(
            $jwt,
            $jwt->setKeys($this->getKeyContainer()),
            'setKeys did not return $this'
        );
    }

    public function vectors()
    {
        // [
        //  encoded JWT,
        //  claims,
        //  KeyContainer,
        //  should be signed
        // ]
        $kc = function (Algorithm $a, Secret $s) {
            return (new KeyContainer())
                ->addKey(1, $a, $s);
        };
        return [
            [
                'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6MX0.'.
                    'eyJzdWIiOjEyMzQ1Njc4OTAsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ.'.
                    'W1fAsUaR4A6V33l7x2e_AfV0lUMzmPVO_TLqOsixrIA',
                ['sub' => 1234567890, 'name' => 'John Doe', 'admin' => true,],
                $kc(Algorithm::HMAC_SHA_256(), new Secret('secret')),
                true,
            ],
            [
                'eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6MX0.'.
                    'eyJmb28iOiJiYXIifQ.'.
                    '-a8BUkkRJZA0n4-o5fo3i2nN84_hp4wSelj4mWXmKbTI80cZAWsr-OkQqApZKAp4',
                ['foo' => 'bar'],
                $kc(Algorithm::HMAC_SHA_384(), new Secret('secret')),
                true,

            ],
            [
                'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6MX0.'.
                    'eyJzdWIiOjEyMzQ1Njc4OTAsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ.'.
                    '9uDKkUhtLLsOUYzGmuUukxyn30qwDvkrtttSDri5DjeqBy6uuGsxkZuzqTLOR-r8xltGzaopJqGSQuL4Xg9q7w',
                ['sub' => 1234567890, 'name' => 'John Doe', 'admin' => true,],
                $kc(Algorithm::HMAC_SHA_512(), new Secret('secret')),
                true,
            ],
            [
                'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6MX0.'.
                    'eyJ1cmwiOiJodHRwOi8vZXhhbXBsZS5jb20ifQ.'.
                    'TTzMKdmqJqMt93E7CTFsLiDKh0LF9hyt69fOBAS7K1M',
                ['url' => 'http://example.com'],
                $kc(Algorithm::HMAC_SHA_256(), new Secret('secret')),
                true,
            ],
            [
                'eyJhbGciOiJub25lIiwidHlwIjoiSldUIiwia2lkIjoxfQ.'.
                    'eyJ1cmwiOiJodHRwOi8vZXhhbXBsZS5jb20ifQ.'.
                    '',
                ['url' => 'http://example.com'],
                $kc(Algorithm::NONE(), new Secret('')),
                false,
            ],
        ];
    } // vectors

    private function getKeyContainer(): KeyContainer
    {
        return (new KeyContainer())
            ->addKey(1, Algorithm::HMAC_SHA_256(), new Secret('secret'))
            ->addKey(2, Algorithm::HMAC_SHA_384(), new Secret('secret'))
            ->addKey(3, Algorithm::HMAC_SHA_512(), new Secret('secret'))
            ->addKey('HS256', Algorithm::HMAC_SHA_256(), new Secret('secret'))
            ->addKey('HS384', Algorithm::HMAC_SHA_384(), new Secret('secret'))
            ->addKey('HS512', Algorithm::HMAC_SHA_512(), new Secret('secret'))
            ->addKey('none', Algorithm::NONE(), new Secret(''))
            ->setDefaultKey(1);
    }
}
