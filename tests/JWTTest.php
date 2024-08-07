<?php

namespace Firehed\JWT;

use BadMethodCallException;
use Error;
use Firehed\Security\Secret;
use RuntimeException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\DoesNotPerformAssertions;
use PHPUnit\Framework\Attributes\Small;
use PHPUnit\Framework\TestCase;

#[CoversClass(JWT::class)]
#[Small]
class JWTTest extends TestCase
{

    /**
     * @param array<string, mixed> $exp_claims
     */
    #[DataProvider('vectors')]
    public function testDecode(string $vector, array $exp_claims, KeyContainer $keys): void
    {
        $JWT = JWT::fromEncoded($vector, $keys);
        self::assertSame(
            $exp_claims,
            $JWT->getUnverifiedClaims(),
            'Claims did not match'
        );
    }

    public function testGetClaimsThrowsWithBadSignature(): void
    {
        $vector = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Njc4OT'.
            'AsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ.thisisnotvalid';
        $jwt = JWT::fromEncoded($vector, $this->getKeyContainer());
        $this->expectException(InvalidSignatureException::class);
        $jwt->getClaims();
    }

    public function testDecodeAllowsInvalidSignatureWhenExplicitlyConfigured(): void
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
        self::assertSame($expected, $JWT->getUnverifiedClaims());
    }

    public function testDecodeThrowsWithNonDictHeader(): void
    {
        $vector = 'InN0cmluZ3ki.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG'.
            '9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.cYa1rl0kZBcZOjv9HG7bKIBiCzNx9v5IeX0X'.
            'C-JW9Eo';
        self::expectException(RuntimeException::class);
        JWT::fromEncoded($vector, $this->getKeyContainer());
    }

    public function testDecodeThrowsWithNonDictClaims(): void
    {
        $vector = 'eyJraWQiOiJIUzI1NiIsImFsZyI6IkhTMjU2In0.InN0cmluZ3ki.cYa1rl'.
            '0kZBcZOjv9HG7bKIBiCzNx9v5IeX0XC-JW9Eo';
        self::expectException(RuntimeException::class);
        JWT::fromEncoded($vector, $this->getKeyContainer());
    }

    /**
     * @param array<string, mixed> $claims
     */
    #[DataProvider('vectors')]
    public function testEncode(string $vector, array $claims, KeyContainer $keys): void
    {
        $tok = new JWT($claims);
        $tok->setKeys($keys);
        $out = $tok->getEncoded();
        self::assertSame($vector, $out, 'Output did not match test vector');
    }

    public function testEnforceNBF(): void
    {
        self::expectException(TokenNotYetValidException::class);
        JWT::fromEncoded(
            'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.'.
            'eyJuYmYiOjk5OTk5OTk5OTk5OX0.',
            $this->getKeyContainer()->setDefaultKey('none')
        );
    }

    public function testEnforceEXP(): void
    {
        self::expectException(TokenExpiredException::class);
        JWT::fromEncoded(
            'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJleHAiOjF9.',
            $this->getKeyContainer()->setDefaultKey('none')
        );
    }

    public function testSpecifyingEncodingKeyProducesCorrectOutput(): void
    {
        $expected = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6M30.eyJ1c2VyI'.
            'joiRm9vIEJhciJ9.E2gekVU0lErEsIqIWSdG7-32yVhALHr_tZu5DFfWVjM';
        $keys = (new KeyContainer())
            ->addKey(3, Algorithm::HMAC_SHA_256, new Secret('secret'))
            ->addKey(1, Algorithm::HMAC_SHA_384, new Secret('xxx'))
            ->addKey(2, Algorithm::HMAC_SHA_512, new Secret('yyy'));
        $jwt = new JWT(['user' => 'Foo Bar']);
        $jwt->setKeys($keys);
        self::assertSame(
            $expected,
            $jwt->getEncoded(3),
            'Encoded output did not match expected'
        );
    }

    /**
     * Ensures that the key ID header value takes precedence when multiple keys
     * are made available to the decoding method, and the data remains correct.
     */
    public function testGetKeyIDFromDecodedInput(): void
    {
        $data = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6M30.eyJ1c2VyIjoiR'.
            'm9vIEJhciJ9.E2gekVU0lErEsIqIWSdG7-32yVhALHr_tZu5DFfWVjM';
        $kc = (new KeyContainer())
            ->addKey(2, Algorithm::HMAC_SHA_384, new Secret('xxx'))
            ->addKey(3, Algorithm::HMAC_SHA_256, new Secret('secret'))
            ->addKey(4, Algorithm::HMAC_SHA_512, new Secret('yyy'))
            ->setDefaultKey(2);
        $jwt = JWT::fromEncoded($data, $kc);
        self::assertSame(
            3,
            $jwt->getKeyID(),
            '`kid` header was not retreived correctly'
        );
        // use key id 3 to determine secret
        self::assertSame(
            ['user' => 'Foo Bar'],
            $jwt->getClaims(),
            'getClaims was wrong after checking key id'
        );
    }

    public function testNotSettingKeysFails(): void
    {
        $tok = new JWT(['data' => true]);
        // Expect property access before initialization
        $this->expectException(Error::class);
        $tok->getEncoded();
    }

    public function testNewTokenAllowsAccessToClaims(): void
    {
        $data = ['data' => true];
        $tok = new JWT($data);
        self::assertEquals(
            $data,
            $tok->getClaims(),
            'getClaims did not return the provided data'
        );
    }

    public function testDecodeStringWithNoPeriods(): void
    {
        self::expectException(InvalidFormatException::class);
        JWT::fromEncoded('asdfklj290iasdf', $this->getKeyContainer());
    }

    public function testDecodeInvalidJSON(): void
    {
        self::expectException(InvalidFormatException::class);
        // test.test
        JWT::fromEncoded('dGVzdA.dGVzdA.', $this->getKeyContainer());
    }

    public function testNoneAlgorithmRequiresGetUnverifedClaims(): void
    {
        $vector = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJmb28iOiJiYXIifQ.';
        $jwt = JWT::fromEncoded(
            $vector,
            $this->getKeyContainer()->setDefaultKey('none')
        );
        self::expectException(BadMethodCallException::class);
        $jwt->getClaims();
    }

    public function testModifiedAlgorithmTriggersInvalidSignature(): void
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
    }

    #[DoesNotPerformAssertions]
    public function testConstruct(): void
    {
        $jwt = new JWT(['foo' => 'bar']);
    }

    public function testSetKeysReturnsthis(): void
    {
        $jwt = new JWT([]);
        self::assertSame(
            $jwt,
            $jwt->setKeys($this->getKeyContainer()),
            'setKeys did not return $this'
        );
    }

    /**
     * @return array{string, array<string, mixed>, KeyContainer, bool}[]
     */
    public static function vectors(): array
    {
        // [
        //  encoded JWT,
        //  claims,
        //  KeyContainer,
        //  should be signed
        // ]
        $kc = function (Algorithm $alg, Secret $s): KeyContainer {
            return (new KeyContainer())
                ->addKey(1, $alg, $s);
        };
        return [
            [
                'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6MX0.'.
                    'eyJzdWIiOjEyMzQ1Njc4OTAsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ.'.
                    'W1fAsUaR4A6V33l7x2e_AfV0lUMzmPVO_TLqOsixrIA',
                ['sub' => 1234567890, 'name' => 'John Doe', 'admin' => true,],
                $kc(Algorithm::HMAC_SHA_256, new Secret('secret')),
                true,
            ],
            [
                'eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6MX0.'.
                    'eyJmb28iOiJiYXIifQ.'.
                    '-a8BUkkRJZA0n4-o5fo3i2nN84_hp4wSelj4mWXmKbTI80cZAWsr-OkQqApZKAp4',
                ['foo' => 'bar'],
                $kc(Algorithm::HMAC_SHA_384, new Secret('secret')),
                true,

            ],
            [
                'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6MX0.'.
                    'eyJzdWIiOjEyMzQ1Njc4OTAsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ.'.
                    '9uDKkUhtLLsOUYzGmuUukxyn30qwDvkrtttSDri5DjeqBy6uuGsxkZuzqTLOR-r8xltGzaopJqGSQuL4Xg9q7w',
                ['sub' => 1234567890, 'name' => 'John Doe', 'admin' => true,],
                $kc(Algorithm::HMAC_SHA_512, new Secret('secret')),
                true,
            ],
            [
                'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6MX0.'.
                    'eyJ1cmwiOiJodHRwOi8vZXhhbXBsZS5jb20ifQ.'.
                    'TTzMKdmqJqMt93E7CTFsLiDKh0LF9hyt69fOBAS7K1M',
                ['url' => 'http://example.com'],
                $kc(Algorithm::HMAC_SHA_256, new Secret('secret')),
                true,
            ],
            [
                'eyJhbGciOiJub25lIiwidHlwIjoiSldUIiwia2lkIjoxfQ.'.
                    'eyJ1cmwiOiJodHRwOi8vZXhhbXBsZS5jb20ifQ.'.
                    '',
                ['url' => 'http://example.com'],
                $kc(Algorithm::NONE, new Secret('')),
                false,
            ],
        ];
    }

    private function getKeyContainer(): KeyContainer
    {
        return (new KeyContainer())
            ->addKey(1, Algorithm::HMAC_SHA_256, new Secret('secret'))
            ->addKey(2, Algorithm::HMAC_SHA_384, new Secret('secret'))
            ->addKey(3, Algorithm::HMAC_SHA_512, new Secret('secret'))
            ->addKey('HS256', Algorithm::HMAC_SHA_256, new Secret('secret'))
            ->addKey('HS384', Algorithm::HMAC_SHA_384, new Secret('secret'))
            ->addKey('HS512', Algorithm::HMAC_SHA_512, new Secret('secret'))
            ->addKey('none', Algorithm::NONE, new Secret(''))
            ->setDefaultKey(1);
    }
}
