<?php namespace rogoss\OAuth;

interface iTokenUser {
    
    public function parseToken( string $sValue, bool $bBase64=false): iTokenUser ; 
    public function requiresAgent(string $sAgent) : iTokenUser;
    public function requiresNoneExpired() : iTokenUser;

    public function getContent(): string;

}
