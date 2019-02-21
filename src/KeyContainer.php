<?php

namespace Firehed\JWT;

use Firehed\Security\Secret;

class KeyContainer
{

    private $keys;
    private $default;
    private $last;

    public function addKey($id, Algorithm $alg, Secret $secret): self {
        $this->keys[$id] = [$alg, $secret];
        $this->last = $id;
        return $this;
    }

    public function setDefaultKey($id): self {
        $this->default = $id;
        return $this;
    }

    /**
     * @param mixed Key ID
     * @return array [Algorithm, Secret, id]
     */
    public function getKey($id = null): array {
        // Prefer explicitly requested > explicit default > most recently added
        $id = $id ?? $this->default ?? $this->last;
        if ($id === null || !array_key_exists($id, $this->keys)) {
            throw new KeyNotFoundException(
                "No key found with id '$id'");
        }
        list($alg, $secret) = $this->keys[$id];
        return [$alg, $secret, $id];
    }

}
