<?php

namespace rogoss\OAuth;

require_once __DIR__ . "/TokenException.php";

class TokenBase {
    // Token Fields
    //==========================================================================
    /** @property string  Idealy the User-Agent, that the Token was created for */
    protected string $sAgent = "";

    //==========================================================================
    /** @property string  the SHA256 Representation of the Tokens Agent */
    protected string $sAgentToken = "";

    /** @property string  Additional content, that can for example describe the areas, this token is valid in */
    protected string $sContent = "";

    /** @property int The number of Seconds, the Token will stay valid */
    protected int $iTTL = 0;

    // Signature Secret 
    //==========================================================================
    private string $sSecret = "";

    /**
     * @param string $sSignaturSecret a Salt-String, that the contents actual signature will we wrapped in
     */
    public function __construct($sSignaturSecret = "")
    {
        if (!empty($sSignaturSecret) && strlen($sSignaturSecret) < 10)
            throw new TokenException("given secret is to short must at least be 10 characters", TokenException::SECRET_TO_SHORT);

        $this->sSecret = $sSignaturSecret;
    }

    private function toUnsignedArray() : array {
        $aTokenContent = [];
        $sTokenMode = "";


        if (!empty($this->sAgentToken)) {
            $aTokenContent["a"] = $this->sAgentToken;
            $sTokenMode .= "a";
        }

        if ($this->iTTL > 0) {
            $aTokenContent["ttl"] = $this->iTTL;
            $sTokenMode .= "t";
        }

        if (!empty($this->sContent)) {
            $aTokenContent["c"] = $this->sContent;
            $sTokenMode .= 'c';
        }
        $aTokenContent['m'] = $sTokenMode;

        return $aTokenContent;
    }

    protected function getSignature() : string {
        return $this->signArray($this->toUnsignedArray());
    }

    protected function hashAgent($sAgent): string {
        return hash("sha256", $sAgent);
    }

    /**
     * @param array $aToken  - an array containing all Values, for a given token
     * @return string
     */
    private function signArray(array &$aToken): string {
        $sSignaturContent =
            ($aToken['a'] ?? '')
            . ($aToken['m'] ?? '')
            . ($aToken['ttl'] ?? '')
            . ($aToken['c'] ?? '');

        if (empty($this->sSecret))
            return hash("sha256", $sSignaturContent);

        $aSignaturSplitHash = str_split(hash("sha256", $sSignaturContent), 1);
        $iSplitHashLength = count($aSignaturSplitHash);
        $iFoundNums = 0;
        $iFoundSum = 0;

        for ($a = 0; $a < $iSplitHashLength; $a++) {
            switch ($aSignaturSplitHash[$a]) {
                case "0":
                case "1":
                case "2":
                case "3":
                case "4":
                case "5":
                case "6":
                case "7":
                case "8":
                case "9":
                    $iFoundNums++;
                    $iFoundSum += intval($aSignaturSplitHash[$a]);
            }
        }

        $iMagicNr = floor($iFoundSum / $iFoundSum);

        $aToken['s'] = hash(
            "sha256",
            substr($this->sSecret, 0, $iMagicNr)
                . $sSignaturContent
                . substr($this->sSecret, $iMagicNr - 1)
        );

        return $aToken['s'];
    }


    /**
     * Returns a String representation of this token (Including a signature)
     * @param bool $bBase64 - if true, the result will be base64 encoded
     * 
     * @return string - either a JSON-String or Base64-String, depended on $bBase64
     */
    public function toString($bBase64 = false): string
    {
        $aToken = $this->toUnsignedArray();
        $this->signArray($aToken);

        $sOutput = json_encode($aToken);
        return $bBase64 ? base64_encode($sOutput) : $sOutput;
    }

    public function __toString()
    {
        return $this->toString();
    }
}
