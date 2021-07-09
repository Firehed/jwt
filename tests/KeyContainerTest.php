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
     * @return void
     */
    public function testConstruct()
    {
        self::assertInstanceOf(
            KeyContainer::class,
            new KeyContainer()
        );
    }

    /**
     * @covers ::setDefaultKey
     * @return void
     */
    public function testSetDefaultKeyReturnsThis()
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
     * @return void
     */
    public function testAddKeyReturnsThis()
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
     * @return void
     */
    public function testGetKeyReturnsMatchedID()
    {
        $kc = $this->getKeyContainer();
        list($alg, $secret, $id) = $kc->getKey('HS384');
        self::assertSame('HS384', $id, 'Wrong ID');
        self::assertEquals(Algorithm::HMAC_SHA_384, $alg, 'Wrong algorithm');
        self::assertSame('HS384', $secret->reveal(), 'Wrong secret');
    }

    /**
     * @covers ::getKey
     * @return void
     */
    public function testGetKeyReturnsExplicitDefault()
    {
        $kc = $this->getKeyContainer()->setDefaultKey(512);
        list($alg, $secret, $id) = $kc->getKey();
        self::assertSame(512, $id, 'Wrong ID');
        self::assertEquals(Algorithm::HMAC_SHA_512, $alg, 'Wrong algorithm');
        self::assertSame('HS512', $secret->reveal(), 'Wrong secret');
    }

    /**
     * @covers ::getKey
     * @return void
     */
    public function testGetKeyReturnsMostRecentEntryWithNoDefault()
    {
        $kc = $this->getKeyContainer();
        list($alg, $secret, $id) = $kc->getKey();
        self::assertSame('last', $id, 'Wrong ID');
        self::assertEquals(Algorithm::NONE, $alg, 'Wrong algorithm');
        self::assertSame('', $secret->reveal(), 'Wrong secret');
    }

    /**
     * @covers ::getKey
     * @return void
     */
    public function testGetKeyThrowsWhenNoKeyMatchesExplicit()
    {
        $kc = $this->getKeyContainer();
        $this->expectException(KeyNotFoundException::class);
        $kc->getKey('notpresent');
    }

    /**
     * @covers ::getKey
     * @return void
     */
    public function testGetKeyThrowsWhenNoKeyMatchesDefault()
    {
        $kc = $this->getKeyContainer()->setDefaultKey('notpresent');
        $this->expectException(KeyNotFoundException::class);
        $kc->getKey();
    }

    /**
     * @covers ::getKey
     * @return void
     */
    public function testGetKeyThrowsWhenNoKeys()
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
