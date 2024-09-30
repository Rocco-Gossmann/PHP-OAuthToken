<?php namespace rogoss\OAuth;

class TokenException extends \Exception {

    /** @var int Secrets must contain at least 10 characters */
    const SECRET_TO_SHORT = 1;


    /** @var int The given value could be parsed via json_decode */
    const VALUE_NOT_JSON = 2;
    /** @var int the parsed Token contains invalid fields or is missing fields */
    const INVALID_TOKEN_STRUCT = 3;

    /** @var int a token field was required to contain nummeric values, but did not */
    const VALUE_NOT_NUMMERIC = 4;

    /** @var int a token field was required to contain a value, but it does not */
    const VALUE_EMPTY = 5;

    /** @var int a token field was reqired to be represendeted by he hex-string (0-9, a-f) */
    const VALUE_NOT_HASH = 6;

    /** @var int a token did not match the Agent requirement */
    const AGENT_MISSMATCH = 7;

    /** @var int a tokens ttl was reached */
    const TOKEN_EXPIRED = 8;
}