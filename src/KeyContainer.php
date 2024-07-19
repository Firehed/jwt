<?php

namespace Firehed\JWT;

use Firehed\Security\Secret;

class KeyContainer
{

    /** @var array{Algorithm, Secret}[] */
    private array $keys = [];

    private int|string|null $default = null;

    private int|string|null $last = null;

    public function addKey(int|string $id, Algorithm $alg, Secret $secret): self
    {
        $this->keys[$id] = [$alg, $secret];
        $this->last = $id;
        return $this;
    }

    public function setDefaultKey(int|string $id): self
    {
        $this->default = $id;
        return $this;
    }

    /**
     * @return array{Algorithm, Secret, string|int}
     */
    public function getKey(int|string|null $id = null): array
    {
        // Prefer explicitly requested > explicit default > most recently added
        $id = $id ?? $this->default ?? $this->last;
        if ($id === null || !array_key_exists($id, $this->keys)) {
            throw new KeyNotFoundException(
                "No key found with id '$id'"
            );
        }
        [$alg, $secret] = $this->keys[$id];
        return [$alg, $secret, $id];
    }
}
