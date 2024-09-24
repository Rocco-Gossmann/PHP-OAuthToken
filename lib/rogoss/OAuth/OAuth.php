<?php

namespace rogoss\OAuth;

require_once __DIR__ . "/TokenException.php";
require_once __DIR__ . "/Token.php";
require_once __DIR__ . "/TokenConstructor.php";


class OAuth {

    private $sSecret = "";

    public function __construct(string $sSignaturSecret='') {
        if (!empty($sSignaturSecret) && strlen($sSignaturSecret) < 10)
            throw new TokenException("given secret is to short must at least be 10 characters", TokenException::SECRET_TO_SHORT);

        $this->sSecret = $sSignaturSecret;
    }

    public function NewToken(): iTokenGenerator {
        return new TokenConstructor($this->sSecret);
    }
}
