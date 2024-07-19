<?php

declare(strict_types=1);

namespace Firehed\JWT;

use Firehed\Security\Secret;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Small;

#[CoversClass(Codec::class)]
#[Small]
class CodecTest extends TestCase
{
    private Codec $codec;
    private KeyContainer $container;

    public function setUp(): void
    {
        $keyContainer = new KeyContainer();
        $keyContainer->addKey('a', Algorithm::HMAC_SHA_256, new Secret('key-a'));
        $keyContainer->addKey('b', Algorithm::HMAC_SHA_384, new Secret('key-b'));
        $keyContainer->addKey('c', Algorithm::HMAC_SHA_512, new Secret('key-c'));
        $this->codec = new Codec($keyContainer);
        $this->container = $keyContainer;
    }

    public function testRoundtrip(): void
    {
        $claims = [
            Claim::ISSUED_AT => time(),
        ];
        $encoded = $this->codec->encode($claims);
        $decoded = $this->codec->decode($encoded);

        self::assertSame($claims, $decoded->getClaims());
        self::assertSame('c', $decoded->getKeyID());
    }

    public function testRoundtripWithSpecifiedKeyId(): void
    {
        $this->container->setDefaultKey('a');
        $claims = [
            Claim::ISSUED_AT => time(),
        ];
        $encoded = $this->codec->encode($claims, 'b');
        $decoded = $this->codec->decode($encoded);

        self::assertSame($claims, $decoded->getClaims());
        self::assertSame('b', $decoded->getKeyID());
    }

    public function testRoundtripWithContainerDefaultKeyId(): void
    {
        $this->container->setDefaultKey('a');
        $claims = [
            Claim::ISSUED_AT => time(),
        ];
        $encoded = $this->codec->encode($claims);
        $decoded = $this->codec->decode($encoded);

        self::assertSame($claims, $decoded->getClaims());
        self::assertSame('a', $decoded->getKeyID());
    }
}
