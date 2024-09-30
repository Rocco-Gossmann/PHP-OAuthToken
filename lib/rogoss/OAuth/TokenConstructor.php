<?php namespace rogoss\OAuth;

require_once __DIR__ . "/TokenBase.php";
require_once __DIR__ . "/iTokenGenerator.php";


class TokenConstructor extends TokenBase implements iTokenGenerator {

    public function setAgent(string $sAgent): iTokenGenerator {
        $this->sAgent = $sAgent;
        $this->sAgentToken = empty($this->sAgent) ? "" : $this->hashAgent($this->sAgent);
        return $this;
    }

    public function setTTL(int $iTTL): iTokenGenerator {
        $this->iTTL = time() + $iTTL;
        return $this;
    }

    public function setContent(string $sContent): iTokenGenerator {
        $this->sContent = $sContent; 
        return $this;
    }

    public function finalize(bool $bBase64 = false) : string {
        return $this->toString($bBase64); 
    }

}
