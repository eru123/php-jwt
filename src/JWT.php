<?php

namespace eru123\jwt;

use DateTime;
use Exception;
use stdClass;

class JWT
{
    public static $default_algo = 'HS256';

    public static function decode(string $jwt, string $key = null): array
    {
        if (empty($key)) {
            throw new Exception('Invalid secret key', 400);
        }

        $timestamp = time();
        $tks = explode('.', $jwt);

        if (count($tks) !== 3) {
            throw new Exception('Wrong number of segments', 401);
        }

        list($headb64, $bodyb64, $cryptob64) = $tks;

        $headerRaw = static::urlsafeB64Decode($headb64);
        if (null === ($header = static::jsonDecode($headerRaw))) {
            throw new Exception('Invalid header encoding', 401);
        }

        $payloadRaw = static::urlsafeB64Decode($bodyb64);
        if (null === ($payload = static::jsonDecode($payloadRaw))) {
            throw new Exception('Invalid claims encoding', 401);
        }

        $sig = static::urlsafeB64Decode($cryptob64);


        if (is_array($payload)) {
            $payload = (object) $payload;
        }

        if (!$payload instanceof stdClass) {
            throw new Exception('Invalid claims encoding', 401);
        }

        if (empty($header->alg)) {
            throw new Exception('Empty algorithm', 401);
        }

        if (!static::constantTimeEquals('HS256', $header->alg)) {
            throw new Exception('Algorithm not allowed', 401);
        }

        if (!static::verify("{$headb64}.{$bodyb64}", $sig, $key)) {
            throw new Exception('Signature verification failed', 401);
        }

        if (isset($payload->nbf) && $payload->nbf > $timestamp) {
            throw new Exception(
                'Cannot handle token prior to ' . date(DateTime::ISO8601, $payload->nbf),
                401
            );
        }

        if (isset($payload->iat) && $payload->iat > $timestamp) {
            throw new Exception(
                'Cannot handle token prior to ' . date(DateTime::ISO8601, $payload->iat),
                401
            );
        }

        if (isset($payload->exp) && $timestamp >= $payload->exp) {
            throw new Exception('Expired token', 401);
        }

        return (array) $payload;
    }

    public static function encode(array $payload, string $key = null): string
    {
        if (empty($key)) {
            throw new Exception('Invalid secret key', 400);
        }

        $tmc_keys = ['iat', 'nbf', 'exp', 'jti'];
        foreach ($tmc_keys as $tk) {
            if (isset($payload[$tk]) && !is_numeric($payload[$tk])) {
                throw new Exception("Invalid value for $tk", 400);
            }
        }

        $header = ['typ' => 'JWT', 'alg' => 'HS256'];
        $segments = [];
        $segments[] = static::urlsafeB64Encode((string) static::jsonEncode($header));
        $segments[] = static::urlsafeB64Encode((string) static::jsonEncode($payload));
        $signing_input = implode('.', $segments);

        $signature = static::sign($signing_input, $key);
        $segments[] = static::urlsafeB64Encode($signature);

        return implode('.', $segments);
    }

    public static function sign(string $msg, string $key): string
    {
        return hash_hmac('SHA256', $msg, $key, true);
    }

    private static function verify(string $msg, string $signature, string $key = null): bool
    {
        if (empty($key)) {
            throw new Exception('Invalid secret key', 400);
        }

        $hash = hash_hmac('SHA256', $msg, $key, true);
        return static::constantTimeEquals($hash, $signature);
    }

    public static function jsonDecode(string $input)
    {
        $obj = json_decode($input, false, 512, JSON_BIGINT_AS_STRING);

        if ($errno = json_last_error()) {
            static::handleJsonError($errno);
        } elseif ($obj === null && $input !== 'null') {
            throw new Exception('Null result with non-null input');
        }
        return $obj;
    }

    public static function jsonEncode(array $input): string
    {
        if (PHP_VERSION_ID >= 50400) {
            $json = json_encode($input, JSON_UNESCAPED_SLASHES);
        } else {
            $json = json_encode($input);
        }
        if ($errno = json_last_error()) {
            static::handleJsonError($errno);
        } elseif ($json === 'null' && $input !== null) {
            throw new Exception('Null result with non-null input');
        }
        if ($json === false) {
            throw new Exception('Failed to encode JSON');
        }
        return $json;
    }

    public static function urlsafeB64Decode(string $input): string
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

    public static function urlsafeB64Encode(string $input): string
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    public static function constantTimeEquals(string $left, string $right): bool
    {
        if (function_exists('hash_equals')) {
            return hash_equals($left, $right);
        }
        $len = min(static::safeStrlen($left), static::safeStrlen($right));

        $status = 0;
        for ($i = 0; $i < $len; $i++) {
            $status |= (ord($left[$i]) ^ ord($right[$i]));
        }
        $status |= (static::safeStrlen($left) ^ static::safeStrlen($right));

        return ($status === 0);
    }

    private static function handleJsonError(int $errno): void
    {
        $messages = [
            JSON_ERROR_DEPTH => 'Maximum stack depth exceeded',
            JSON_ERROR_STATE_MISMATCH => 'Invalid or malformed JSON',
            JSON_ERROR_CTRL_CHAR => 'Unexpected control character found',
            JSON_ERROR_SYNTAX => 'Syntax error, malformed JSON',
            JSON_ERROR_UTF8 => 'Malformed UTF-8 characters'
        ];

        throw new Exception(
            isset($messages[$errno])
            ? $messages[$errno]
            : 'Unknown JSON error: ' . $errno,
            401
        );
    }

    private static function safeStrlen(string $str): int
    {
        if (function_exists('mb_strlen')) {
            return mb_strlen($str, '8bit');
        }
        return strlen($str);
    }
}