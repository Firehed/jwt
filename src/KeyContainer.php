<?php

namespace Firehed\JWT;

use Firehed\Security\Secret;

class KeyContainer
{

    private $keys;
    private $default;

    public function addKey($id, Algorithm $alg, Secret $secret): self {
        $this->keys[$id] = [$alg, $secret];
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
        // If ID not provided, use the default
        if ($id === null) {
            $id = $this->default;
        }
        // If a default was not provided, use the most recently added key
        if ($id === null) {
            end($this->keys);
            $id = key($this->keys);
        }
        if (!array_key_exists($id, $this->keys)) {
            throw new KeyNotFoundException(
                "No key found with id '$id'");
        }
        list($alg, $secret) = $this->keys[$id];
        return [$alg, $secret, $id];
    }

}
