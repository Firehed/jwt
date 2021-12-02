<?php

namespace Firehed\JWT;

use Firehed\Security\Secret;

class KeyContainer
{

    /** @var array{Algorithm::*, Secret}[] */
    private $keys = [];

    /** @var int|string|null */
    private $default;

    /** @var int|string|null */
    private $last;

    /**
     * @param Algorithm::* $alg
     * @param array-key $id
     */
    public function addKey($id, string $alg, Secret $secret): self
    {
        $this->keys[$id] = [$alg, $secret];
        $this->last = $id;
        return $this;
    }

    /**
     * @param array-key $id
     */
    public function setDefaultKey($id): self
    {
        $this->default = $id;
        return $this;
    }

    /**
     * @param ?array-key $id Key ID
     * @return array{Algorithm::*, Secret, string|int}
     */
    public function getKey($id = null): array
    {
        // Prefer explicitly requested > explicit default > most recently added
        $id = $id ?? $this->default ?? $this->last;
        if ($id === null || !array_key_exists($id, $this->keys)) {
            throw new KeyNotFoundException(
                "No key found with id '$id'"
            );
        }
        list($alg, $secret) = $this->keys[$id];
        return [$alg, $secret, $id];
    }
}
