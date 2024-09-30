<?php namespace rogoss\OAuth;

require_once __DIR__ . "/TokenBase.php";

class Token extends TokenBase {

    /** @ignore */
    public function validateString(string $sField, $mValue) : string {
        $sValue = trim("". $mValue);
        if(empty($sValue)) 
            throw new TokenException("value of '{$sField}' is empty", TokenException::VALUE_EMPTY);

        return $sValue;
    }

    /** @ignore */
    public function validateHash(string $sField, $mValue) : string {
        $sValue = trim("". $mValue);
        if(!preg_match("/^[0-9a-f]+$/i", $sValue)) 
            throw new TokenException("value of '{$sField}' is not a hash", TokenException::VALUE_NOT_HASH);

        return $sValue;
    }

    /** @ignore */
    public function validateInt(string $sField, $mValue) : int {
        if(!is_numeric($mValue))
            throw new TokenException("value of '{$sField}' is not numeric", TokenException::VALUE_NOT_NUMMERIC);

        return intval($mValue);
    }

    public static function blank() : static {
        return new static(); 
    }

    public static function withSecret(string $sSecret) : static {
        return new static($sSecret); 
    }

    public function parseToken(string $sValue, bool $bBase64 = false) {

        if($bBase64)
            $sValue = base64_decode($sValue);

        if(empty($aJSON = json_decode($sValue, true))) 
            throw new TokenException("given Value is not JSON", TokenException::VALUE_NOT_JSON);
        
        if(!isset($aJSON['s']))
            throw new TokenException("Missing field 's' ", TokenException::INVALID_TOKEN_STRUCT);

        $sSignature = $aJSON['s'];
        unset($aJSON['s']);


        if(!isset($aJSON['m']))
            throw new TokenException("Missing field 'm' ", TokenException::INVALID_TOKEN_STRUCT);

        $sTokenMode = $aJSON['m'];
        unset($aJSON['m']);

        $aModes = str_split($sTokenMode);
        $iModeCnt = count($aModes);

        for($a = 0; $a < $iModeCnt; $a++) {
            $sMode = $aModes[$a];

            switch($sMode) {
                case "a": 
                    $sField = "a";
                    $sProp = "sAgentToken";
                    $sValidator = "validateHash";
                    break;
                    
                case "t":
                    $sField = "ttl";
                    $sProp = "iTTL";
                    $sValidator = "validateInt";
                    break;

                case "c":
                    $sField = "c";
                    $sProp = "sContent";
                    $sValidator = "validateString";
                    break;
                    
                break;
                default:
                    throw new TokenException("unknown tokenmode '{$sTokenMode}'", TokenException::INVALID_TOKEN_STRUCT);
            }


            if(!isset($aJSON[$sField]))
                throw new TokenException("token is missing field '{$sField}'", TokenException::INVALID_TOKEN_STRUCT);

            if(empty($aJSON[$sField]))
                throw new TokenException("token field '{$sField}' is empty", TokenException::VALUE_EMPTY);

            $mValue = $aJSON[$sField];
            unset($aJSON[$sField]);

            $this->$sProp = $this->$sValidator($sField, $mValue);
        }

        if(count($aJSON) > 0)
            throw new TokenException("token fields do not match with given mode (".implode(", ", array_keys($aJSON)). ")", TokenException::INVALID_TOKEN_STRUCT);

        if(strcmp($sSignature, $this->getSignature())) {
            throw new TokenException("token signature missmatch", TokenException::INVALID_TOKEN_STRUCT);
        }

        return $this;
    }

    public function requiresAgent($sAgent): Token {

        if(strcmp($this->hashAgent($sAgent), $this->sAgentToken))
            throw new TokenException("token agent missmatch", TokenException::AGENT_MISSMATCH);

        return $this;
    }

    public function requiresNoneExpired(): Token {
        
        if($this->iTTL > 0 and (time() - $this->iTTL) >= 0)
            throw new TokenException("token expired", TokenException::TOKEN_EXPIRED);

        return $this;
    }

    public function getContent(): string {
        return $this->sContent;
    }

    private function __construct($sSecret = "") { 
        parent::__construct($sSecret);
    }
}
