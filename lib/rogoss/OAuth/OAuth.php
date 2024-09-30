<?php

namespace rogoss\OAuth;

require_once __DIR__ . "/TokenException.php";
require_once __DIR__ . "/TokenConstructor.php";
require_once __DIR__ . "/Token.php";


class OAuth
{

    public static function withSecret($sSecret)
    {
        return new static($sSecret);
    }

    public static function blank()
    {
        return new static();
    }

    private $sSecret = "";

    private function __construct(string $sSignaturSecret = '')
    {
        if (!empty($sSignaturSecret) && strlen($sSignaturSecret) < 10)
            throw new TokenException("given secret is to short must at least be 10 characters", TokenException::SECRET_TO_SHORT);

        $this->sSecret = $sSignaturSecret;
    }

    public function NewToken(): iTokenGenerator
    {
        return new TokenConstructor($this->sSecret);
    }

    public function LoadToken(string $sToken, $bBase64 = false): iTokenUser
    {
        return Token::withSecret($this->sSecret)
            ->parseToken($sToken, $bBase64);
    }
}
