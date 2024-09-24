<?php namespace rogoss\OAuth;

require_once __DIR__ . "/TokenBase.php";
require_once __DIR__ . "/iTokenGenerator.php";


class TokenConstructor extends TokenBase implements iTokenGenerator {

    public function setAgent(string $sAgent): iTokenGenerator {
        $this->sAgent = $sAgent;
        return $this;
    }

    public function setTTL(int $iTTL): iTokenGenerator {
        $this->iTTL = $iTTL;
        return $this;
    }

    public function finalize(bool $bBase64 = false) : string {
        return $this->toString($bBase64); 
    }

}
