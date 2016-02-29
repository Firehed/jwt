# JWT - JSON Web Tokens

## Installation
`composer require firehed/jwt`

## Usage
Basic encoding example:

```
<?php
require_once 'vendor/autoload.php';
use Firehed\JWT\JWT;
use Firehed\JWT\Algorithm;

$data = [
	'some' => 'data',
	'that' => 'you want to encode',
];
$token = new JWT($data);
$token->setAlgorithm(Algorithm::HMAC_SHA_256());
$jwt_string = $token->encode('your application secret key');
```

Basic decoding example:

```
<?php
require_once 'vendor/autoload.php';
use Firehed\JWT\JWT;
use Firehed\JWT\Algorithm;

$jwt_string = 'some.jwt.string';
$token = JWT::decode($jwt_string);
$token->verify(Algorithm::HMAC_SHA_256(), 'your application secret key');
$data = $token->getClaims();
```

## Security: Signing Keys

### Generation

The HMAC-SHA family of algorithms supports a key length of up to 512 bits (64 bytes). It is recommended to use the longest supported key.

If on PHP>=7, use `random_bytes()`: `$secret = random_bytes(64)`;

On PHP<=5, read from `/dev/urandom` or use the [`random_compat`](https://github.com/paragonie/random_compat) library: `$secret = file_get_contents('/dev/urandom', null, null, 0, 64)`.

Since these probably contain binary data, it's best to store them base64-encoded:

```
$secret = random_bytes(64);
$encoded = base64_encode($secret);
```

Your configuration file, explained below, should `base64_decode` the encoded string before returning it

### IDs and rotation

It is **highly recommended** to regularly rotate your signing keys, and the JWT spec makes this easy to handle thanks to the `kid` header. The API handles this for you automatically with `getKeyID()` and `setKeyID` methods.

In your application config, have multiple keys and their IDs defined:

```
$jwt_keys = [
    '20160101' => [
        'alg' => Firehed\JWT\Algorithm::HMAC_SHA_256(),
        'secret' => base64_decode('string+generated/earlier'),
    ],
    '20160201' => [
        'alg' => Firehed\JWT\Algorithm::HMAC_SHA_256(),
        'secret' => base64_decode('other+string/generated'),
    ],
];
```

To get and use the most recent keys, use the standard `end()`, `current()`, and `key()` array functions:

```
end($jwt_keys);
list($algorithm, $secret) = current($jwt_keys);
$keyID = key($jwt_keys);
```

When verifying a token, get its specified key ID with `getKeyID()` and use that to index into `$jwt_keys`, using the returned values in the subsequent `verify` call:

```
$token = JWT::decode($some_string);
$keyID = $token->getKeyID();
if (!isset($jwt_keys[$keyID])) {
  throw new Exception('Key not found');
}
list($alg, $secret) = $jwt_keys[$keyID];
$token->verify($alg, $secret);
$data = $token->getClaims();
```

For additional examples, look at the implementation of `Firehed\JWT\SessionHandler::read()` and `::write()`, which support key management, and the unit tests.

Note: key ID can take any scalar format. The example above uses a datestamp, but sequential integers are also fine. It is recommended to use something semantically meaningful to the application, but not in any way meaningful to the end-user.

## Security: Exception Handling

When calling `getClaims()` or `verify()`, an exception may be thrown if the signature cannot be verified or the time validity specified in standard `nbf` or `exp` claims is out of line.

Be prepared to catch `InvalidSignatureException`, `TokenExpiredException`, and `TokenNotYetValidException` when calling those methods. 

If an invalid token is passed to `JWT::decode()`, an `InvalidFormatException` will be thrown.

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

As of v1.1.0, the following algorithms are supported:

* `none`
* `HS256` (HMAC-SHA256)
* `HS384` (HMAC-SHA384)
* `HS512` (HMAC-SHA512)

Because the `none` algorithm is inherently insecure, the encoded data may only be accessed with the `getUnverifiedClaims()` API call. Calling `verify()` with the `none` algorithm will do nothing. This is to call explicit attention to the fact that the data cannot be trusted. It is strongly recommended to never use the `none` algorithm.

The algorithm in the header is intentionally ignored during verification to avoid [algorithm-swapping attacks](https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/). This library encourages the use of the `kid` (Key ID) header instead. Asymmetric keys are not supported at this time.

## Sessions

Because JWTs are cryptographically signed, it's now both possible and practical to keep basic session handling completely client-side, removing the dependency on a database connection or the filesystem (and the complexity of scaling that to multiple servers). A class implementing PHP's `SessionHandlerInterface` is included to make this easier.

There are some very important considerations:

1. The JWT session cookie will use the values from `session_get_cookie_params`. **PHP HAS INSECURE DEFAULT VALUES FOR THESE**, and you must reconfigure them with `session_set_cookie_params` to ensure the `secure` and `httponly` cookie flags are set. This is not done automatically nor enforced to make local testing easier.

2. The session MUST NOT contain sensitive information. JWTs *are not encrypted*, just encoded and signed. You must be OK with any data in the session being visible to the user.

3. Because this uses only cookies for storage, there is very limited space available (~4096b for all cookies) and all future network requests will incur the overhead. This makes basic authentication info (e.g. `$_SESSION['user_id'] = 12345;`) and state management practical, but a poor choice if your sessions contain a lot of data or you use several other cookies.

4. Because the data is stored entirely client-side, it will be impossible to build functionality like "log me out everywhere" if used to store authentication data.

5. Like any other session management, the whole thing is pointless if not done over HTTPS.

6. The concept of a session ID is largely ignored

Whenever possible, the `SessionHandler` class attempts to use existing PHP configuration for session handling to be a drop-in replacement.

That out of the way, here's how it's done:

### Session Example

```
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

$handler = new Firehed\JWT\SessionHandler([
    '20160228' => [
        'alg' => Firehed\JWT\Algorithm::HMAC_SHA_256(),
        'secret' => 'your application secret',
    ],
]);

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

Note that if multiple keys are provided to the `SessionHandler` constructor, the latest one will always be used, but reading from older ones will still be supported. This makes key rotation very simple.