<?php
declare(strict_types=1);

namespace Firehed\JWT;

use Firehed\Security\Secret;

/**
 * @coversDefaultClass Firehed\JWT\KeyContainer
 * @covers ::<protected>
 * @covers ::<private>
 */
class KeyContainerTest extends \PHPUnit\Framework\TestCase
{

    /**
     */
    public function testConstruct(): void
    {
        self::assertInstanceOf(
            KeyContainer::class,
            new KeyContainer()
        );
    }

    /**
     * @covers ::setDefaultKey
     */
    public function testSetDefaultKeyReturnsThis(): void
    {
        $kc = new KeyContainer();
        self::assertSame(
            $kc,
            $kc->setDefaultKey(3),
            'setDefaultKey did not return $this'
        );
    }

    /**
     * @covers ::addKey
     */
    public function testAddKeyReturnsThis(): void
    {
        $kc = new KeyContainer();
        self::assertSame(
            $kc,
            $kc->addKey('id', Algorithm::HMAC_SHA_256, new Secret('secret')),
            'addKey did not return $this'
        );
    }

    /**
     * @covers ::getKey
     */
    public function testGetKeyReturnsMatchedID(): void
    {
        $kc = $this->getKeyContainer();
        list($alg, $secret, $id) = $kc->getKey('HS384');
        self::assertSame('HS384', $id, 'Wrong ID');
        self::assertEquals(Algorithm::HMAC_SHA_384, $alg, 'Wrong algorithm');
        self::assertSame('HS384', $secret->reveal(), 'Wrong secret');
    }

    /**
     * @covers ::getKey
     */
    public function testGetKeyReturnsExplicitDefault(): void
    {
        $kc = $this->getKeyContainer()->setDefaultKey(512);
        list($alg, $secret, $id) = $kc->getKey();
        self::assertSame(512, $id, 'Wrong ID');
        self::assertEquals(Algorithm::HMAC_SHA_512, $alg, 'Wrong algorithm');
        self::assertSame('HS512', $secret->reveal(), 'Wrong secret');
    }

    /**
     * @covers ::getKey
     */
    public function testGetKeyReturnsMostRecentEntryWithNoDefault(): void
    {
        $kc = $this->getKeyContainer();
        list($alg, $secret, $id) = $kc->getKey();
        self::assertSame('last', $id, 'Wrong ID');
        self::assertEquals(Algorithm::NONE, $alg, 'Wrong algorithm');
        self::assertSame('', $secret->reveal(), 'Wrong secret');
    }

    /**
     * @covers ::getKey
     */
    public function testGetKeyThrowsWhenNoKeyMatchesExplicit(): void
    {
        $kc = $this->getKeyContainer();
        $this->expectException(KeyNotFoundException::class);
        $kc->getKey('notpresent');
    }

    /**
     * @covers ::getKey
     */
    public function testGetKeyThrowsWhenNoKeyMatchesDefault(): void
    {
        $kc = $this->getKeyContainer()->setDefaultKey('notpresent');
        $this->expectException(KeyNotFoundException::class);
        $kc->getKey();
    }

    /**
     * @covers ::getKey
     */
    public function testGetKeyThrowsWhenNoKeys(): void
    {
        $kc = new KeyContainer();
        $this->expectException(KeyNotFoundException::class);
        $kc->getKey();
    }

    private function getKeyContainer(): KeyContainer
    {
        return (new KeyContainer())
            ->addKey(256, Algorithm::HMAC_SHA_256, new Secret('HS256'))
            ->addKey(384, Algorithm::HMAC_SHA_384, new Secret('HS384'))
            ->addKey(512, Algorithm::HMAC_SHA_512, new Secret('HS512'))
            ->addKey('HS256', Algorithm::HMAC_SHA_256, new Secret('HS256'))
            ->addKey('HS384', Algorithm::HMAC_SHA_384, new Secret('HS384'))
            ->addKey('HS512', Algorithm::HMAC_SHA_512, new Secret('HS512'))
            ->addKey('last', Algorithm::NONE, new Secret(''));
            ;
    }
}
