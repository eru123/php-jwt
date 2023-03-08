# php-jwt
Simple and Straightforward JWT Library

```php
<?php

require_once 'vendor/autoload.php';

use eru123\jwt\JWT;

$payload = [
    'hello' => 'world',
];
$key = 'secret';
$token = JWT::encode($payload, $key); // eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIn0.bqxXg9VwcbXKoiWtp-osd0WKPX307RjcN7EuXbdq-CE
$decoded = JWT::decode($token, $key); // {"hello":"world"}
```
