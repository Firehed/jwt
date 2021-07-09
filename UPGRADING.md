# Updating to 3.0

To migrate from 2.x to 3.0, the only necessary change is updating how you use Algorithm:

```diff
 $keys = new JWT\KeyContainer();
-$keys->addKey(1, JWT\Algorithm::HMAC_SHA_256(), new Secret('some secret key'));
+$keys->addKey(1, JWT\Algorithm::HMAC_SHA_256, new Secret('some secret key'));
```

This is in preparation for PHP 8.1, which will offer native support for enums.
