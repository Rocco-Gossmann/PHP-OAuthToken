<?php namespace Tests;

    require_once __DIR__ . "/lib/rogoss/OAuth/OAuth.php";

    use \PHPUnit\Framework\TestCase;
    use \rogoss\OAuth\TokenException;
    use \rogoss\OAuth\OAuth;

    class TestOAuth extends TestCase {

        const SECRET = "abcdefghijk";

        public function testOAuthInstanciation_WithToShortKey() {
            $this->expectException('\rogoss\OAuth\TokenException');
            $this->expectExceptionCode(TokenException::SECRET_TO_SHORT);
            $_ = new OAuth("123");
        }

        public function testOAuthInstanciation() {
            $this->assertInstanceOf('\rogoss\OAuth\OAuth', new OAuth(), "instantiation without secret" );
            $this->assertInstanceOf('\rogoss\OAuth\OAuth', new OAuth(self::SECRET), "instantiation with valid secret" );
        }

        public function testGeneratorInstanciation() {
            $this->assertInstanceOf(
                '\rogoss\OAuth\iTokenGenerator', 
                (new OAuth(self::SECRET))->NewToken(),
            );
        }
        
        function testEmptyTokenGeneration() {
            $oGenerator = (new OAuth(self::SECRET))->NewToken();

            $this->assertNotEmpty(
                $sEmptyToken = $oGenerator->finalize()
            );

            $this->assertIsArray(
                $aTokenJSON = json_decode($sEmptyToken, true), 
                "Token did not Parse in JSON"
            );

            $this->assertArrayHasKey("s", $aTokenJSON, "token missing 's' field (signature)");
            $this->assertArrayHasKey("m", $aTokenJSON, "token missing 'm' field (mode)");
            $this->assertEquals("", $aTokenJSON['m'], 'field "m" was not empty, despite not token limits were given');

        }

    }
