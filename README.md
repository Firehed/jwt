# JWT - JSON Web Tokens

[![Tests](https://github.com/Firehed/jwt/actions/workflows/test.yml/badge.svg)](https://github.com/Firehed/jwt/actions/workflows/test)
[![codecov](https://codecov.io/gh/Firehed/jwt/branch/master/graph/badge.svg)](https://codecov.io/gh/Firehed/jwt)

## Installation
`composer require firehed/jwt`

## Usage
Basic encoding example:

```php
<?php
require_once 'vendor/autoload.php';
use Firehed\JWT;
use Firehed\Security\Secret;

$keys = new JWT\KeyContainer();
$keys->addKey(1, JWT\Algorithm::HmacSha256, new Secret('some secret key'));

$data = [
	'some' => 'data',
	'that' => 'you want to encode',
];
$token = new JWT($data);
$token->setKeys($keys);
$jwt_string = $token->getEncoded();
```

Basic decoding example:

```php
<?php
require_once 'vendor/autoload.php';

use Firehed\JWT;
use Firehed\Security\Secret;

$keys = new JWT\KeyContainer();
$keys->addKey(1, JWT\Algorithm::HmacSha256, new Secret('some secret key'));


$jwt_string = 'some.jwt.string';
$token = JWT::fromEncoded($jwt_string, $keys);
$data = $token->getClaims();
```

## Security: Signing Keys

### Generation

The HMAC-SHA family of algorithms supports a key length of up to 512 bits (64 bytes). It is recommended to use the longest supported key.

If on PHP>=7, use `random_bytes()`: `$secret = random_bytes(64)`;

Since these probably contain binary data, it's best to store them base64-encoded:

```
$secret = random_bytes(64);
$encoded = base64_encode($secret);
```

Your configuration file, explained below, should `base64_decode` the encoded string before returning it

### IDs and rotation

It is **highly recommended** to regularly rotate your signing keys, and the JWT spec makes this easy to handle thanks to the `kid` header. Encoded output will always include the key id used to sign the token, and that value will automatically be used during decoding.

In your application config, have multiple keys and their IDs defined:

```php
$keys = new KeyContainer();
$keys->addKey('20160101',
              Algorithm::HmacSha256,
              new Secret(base64_decode('string+generated/earlier')))
     ->addKey('20160201',
              Algorithm::HmacSha256,
              new Secret(base64_decode('other+string/generated')));
```

Simply adding additional keys to the container should more-or-less automatically handle key rotation for all new tokens, but your application may behave in a different way that doesn't ensure this is the case.

By default, the `KeyContainer` will use the most recently added key if one is not explicitly requested. You may override this by explicitly setting a default key:

`$keys->setDefaultKey('20160101');`

Note: key ID can take any scalar format. The example above uses a datestamp, but sequential integers are also fine. It is recommended to use something semantically meaningful to the application, but not in any way meaningful to the end-user.

## Security: Exception Handling

When calling `getClaims()`, an exception may be thrown if the signature cannot be verified or the time validity specified in standard `nbf` or `exp` claims is out of line.

Be prepared to catch `InvalidSignatureException`, `TokenExpiredException`, and `TokenNotYetValidException` when calling those methods.

If an invalid token is passed to `JWT::fromEncoded()`, an `InvalidFormatException` will be thrown.

Exception tree:

```
Exception
 |--Firehed\JWT\JWTException
     |--Firehed\JWT\InvalidFormatException
     |--Firehed\JWT\InvalidSignatureException
     |--Firehed\JWT\TokenExpiredException
     |--Firehed\JWT\TokenNotYetValidException
```

## Algorithm Support

As of v2.0.0, the following algorithms are supported:

* `none`
* `HS256` (HMAC-SHA256)
* `HS384` (HMAC-SHA384)
* `HS512` (HMAC-SHA512)

Because the `none` algorithm is inherently insecure, the encoded data may only be accessed with the `getUnverifiedClaims()` API call. This is to call explicit attention to the fact that the data cannot be trusted. It is strongly recommended to never use the `none` algorithm.

The algorithm in the header is intentionally ignored during verification to avoid [algorithm-swapping attacks](https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/). This library instead uses the `kid` (Key ID) header, matching the value to the keys available in the `KeyContainer`. Asymmetric keys are not supported at this time.

## Sessions

Because JWTs are cryptographically signed, it's now both possible and practical to keep basic session handling completely client-side, removing the dependency on a database connection or the filesystem (and the complexity of scaling that to multiple servers). A class implementing PHP's `SessionHandlerInterface` is included to make this easier.

Generally speaking, storing session data other than identifiers client-side *is a bad decision*. It's useful for quick prototying, or in extremely resource-constrained environments.

There are some very important considerations:

1. The JWT session cookie will use the values from `session_get_cookie_params`. **PHP HAS INSECURE DEFAULT VALUES FOR THESE**, and you must reconfigure them with `session_set_cookie_params` to ensure the `secure` and `httponly` cookie flags are set. This is not done automatically nor enforced to make local testing easier.

2. The session MUST NOT contain sensitive information. JWTs *are not encrypted*, just encoded and signed. You must be OK with any data in the session being visible to the user.

3. Because this uses only cookies for storage, there is very limited space available (~4096b for all cookies) and all future network requests will incur the overhead. This makes basic authentication info (e.g. `$_SESSION['user_id'] = 12345;`) and state management practical, but a poor choice if your sessions contain a lot of data or you use several other cookies.

4. Because the data is stored entirely client-side, it will be largely impractical to build functionality like "log me out everywhere" if used to store authentication data.

5. Like any other session management, the whole thing is pointless if not done over HTTPS.

6. The concept of a session ID is largely ignored

Whenever possible, the `SessionHandler` class attempts to use existing PHP configuration for session handling to be a drop-in replacement.

That out of the way, here's how it's done:

### Session Example

```php
<?php
ini_set('session.use_cookies', 0); // Without this, PHP will also send a PHPSESSID cookie, which we neither need nor care about
session_set_cookie_params(
	$lifetime = 0,
	$path = '/',
	$domain = '',
	$secure = true, // <-- Very important
	$httponly = true // <-- Very important
);

require 'vendor/autoload.php';

use Firehed\JWT;
use Firehed\Security\Secret;

$keys = new JWT\KeyContainer();
$keys->addKey(1, JWT\Algorithm::HmacSha256, new Secret('some secret key'));

$handler = new Firehed\JWT\SessionHandler($keys);

session_set_save_handler($handler);

try {
    session_start();
    $_SESSION['user_id'] = 12345;
} catch (Firehed\JWT\InvalidSignatureException $e) {
	// The session cookie was tampered with and the signature is invalid
    // You should log this and investigate
    session_destroy();
}
```

`SessionHandler` will always use the default value from the `KeyContainer`. That means the most recently key will be used unless one was specified with `->setDefaultKey()`.
