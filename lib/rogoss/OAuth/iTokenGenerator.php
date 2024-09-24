<?php namespace rogoss\OAuth;

interface iTokenGenerator {
    public function setAgent(string $sAgent): iTokenGenerator;
    public function setTTL(int $iTTL): iTokenGenerator;

    public function finalize(bool $bBase64 = false) : string;
}