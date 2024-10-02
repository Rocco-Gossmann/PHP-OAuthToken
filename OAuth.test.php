<?php

namespace Tests;

require_once __DIR__ . "/OAuth/OAuth.php";

use \PHPUnit\Framework\TestCase;
use \rogoss\OAuth\TokenException;
use \rogoss\OAuth\Token;
use \rogoss\OAuth\OAuth;

class TestOAuth extends TestCase
{

    const SECRET = "abcdefghijk";

    public function setUp(): void
    {
        # Turn on error reporting
        ini_set("display_errors", "on");
        ini_set("error_reporting", "E_ALL");
    }

    public function testOAuthInstanciation_WithToShortKey()
    {
        $this->expectException('\rogoss\OAuth\TokenException');
        $this->expectExceptionCode(TokenException::SECRET_TO_SHORT);
        OAuth::withSecret("123");
    }

    public function testOAuthInstanciation()
    {
        $this->assertInstanceOf('\rogoss\OAuth\OAuth', OAuth::blank(), "instantiation without secret");
        $this->assertInstanceOf('\rogoss\OAuth\OAuth', OAuth::withSecret(self::SECRET), "instantiation with valid secret");
    }

    public function testGeneratorInstanciation()
    {
        $this->assertInstanceOf(
            '\rogoss\OAuth\iTokenGenerator',
            OAuth::withSecret(self::SECRET)->NewToken(),
        );
    }

    function testEmptyTokenGeneration()
    {
        $oGenerator = OAuth::withSecret(self::SECRET)->NewToken();

        $this->assertNotEmpty($sEmptyToken = $oGenerator->finalize());

        $this->assertIsArray(
            $aTokenJSON = json_decode($sEmptyToken, true),
            "Token did not Parse in JSON"
        );

        $this->assertArrayHasKey("s", $aTokenJSON, "Token misses signature");
        $this->assertNotEmpty($aTokenJSON['s'], "signature should not have been empty");

        $this->assertArrayHasKey("m", $aTokenJSON, "Token misses Key");
        $this->assertEmpty($aTokenJSON['m'], "mode should be empty, but is not");

        $this->assertEquals(2, count($aTokenJSON), "Token should only contain 2 values");
    }

    function testEmptyTokenValidity()
    {

        $sEmptyToken = $this->newEmptyToken();

        $oToken = Token::withSecret(self::SECRET);
        $this->assertInstanceOf('\rogoss\OAuth\Token', $oToken, 'Token::blank() should have returned an instance of \rogoss\OAuth\Token');

        $oPrimedToken = $oToken->parseToken($sEmptyToken);
        $this->assertInstanceOf('\rogoss\OAuth\Token', $oPrimedToken, '$oToken->parseToken($sEmptyToken) should have returned an instance of \rogoss\OAuth\Token');
        $this->assertSame($oToken, $oPrimedToken, '$oPrimedToken should be a reference to $oToken, not a Copy');
    }

    function testTokenWithManipulation()
    {
        $this->_tokenModeManipTest_1(hash("sha256", "hello"), "s");
        $this->_tokenModeManipTest_1("a");
        $this->_tokenModeManipTest_1("t");
        $this->_tokenModeManipTest_1("c");
    }

    function testTokenBuilderFullParams()
    {
        $oTokenBase = OAuth::withSecret(self::SECRET)->NewToken();
        $this->assertInstanceOf('\rogoss\OAuth\iTokenGenerator', $oTokenBase, 'NewToken did not return iTokenGenerator');

        $oToken = $oTokenBase->setAgent("Agent A");
        $this->assertSame($oToken, $oTokenBase, "setAgent did not return itself");

        $oToken = $oToken->setTTL(3600);
        $this->assertSame($oToken, $oTokenBase, "setTTL did not return itself");

        $oToken = $oToken->setContent("Hello World");
        $this->assertSame($oToken, $oTokenBase, "setContent did not return itself");

        $sToken = $oToken->finalize(true);
        $this->assertMatchesRegularExpression('/^[a-zA-Z0-9\/\r\n+]*={0,2}$/', $sToken, "Generated token does not seem to be base64");

        $oDecodedTokenBase = OAuth::withSecret(self::SECRET)->LoadToken($sToken, true);
        $this->assertInstanceOf('\rogoss\OAuth\Token', $oDecodedTokenBase, 'Parsed Token did not have the correct class');

        $oDecodedToken = $oDecodedTokenBase->requiresAgent("Agent A");
        $this->assertSame($oDecodedToken, $oDecodedTokenBase, "requiresAgent did not return itself");

        $oDecodedToken = $oDecodedTokenBase->requiresNoneExpired();
        $this->assertSame($oDecodedToken, $oDecodedTokenBase, "requiresAgent did not return itself");

        $this->assertEquals("Hello World", $oDecodedToken->getContent(), "unexpected token content");
    }

    function testTokenWithManipulatedAgent()
    {
        $this->_tokenModeManipTest_2("a", hash("sha256", "yo"));
    }
    function testTokenWithManipulatedTTL()
    {
        $this->_tokenModeManipTest_2("ttl", time() + 7200);
    }
    function testTokenWithManipulatedContent()
    {
        $this->_tokenModeManipTest_2("c", "A,B,C");
    }
    function testTokenWithTimeout()
    {
        $sToken = $this->newFullToken(1);
        sleep(1);

        $this->expectException('\rogoss\OAuth\TokenException');
        $this->expectExceptionCode(TokenException::TOKEN_EXPIRED);

        OAuth::withSecret(self::SECRET)
            ->LoadToken($sToken)
            ->requiresNoneExpired();
    }


    // BM: Private Helpers
    //======================================================================
    private function newEmptyToken(): string
    {
        $sToken = OAuth::withSecret(self::SECRET)->NewToken()->finalize();
        $this->assertNotEmpty($sToken, "this token should not have been empty");
        return $sToken;
    }

    private function newFullToken($iTTL = 2000): string
    {
        return OAuth::withSecret(self::SECRET)
            ->NewToken()
            ->setAgent("Agent A")
            ->setTTL($iTTL)
            ->setContent("A,B")
            ->finalize();
    }

    private function _tokenModeManipTest_1($sMode, $sTokenField = "m")
    {
        $aToken = json_decode($this->newEmptyToken(), true);
        $aToken[$sTokenField] = $sMode;
        $sToken = json_encode($aToken);

        $this->expectException('\rogoss\OAuth\TokenException');
        $this->expectExceptionCode(TokenException::INVALID_TOKEN_STRUCT);

        OAuth::withSecret(self::SECRET)->LoadToken($sToken, false); 
    }

    private function _tokenModeManipTest_2($sTokenField, $mValue)
    {
        $sRawToken = $this->newFullToken();
        $aToken = json_decode($sRawToken, true);
        $aToken[$sTokenField] = $mValue;
        $sToken = json_encode($aToken);

        $this->expectException('\rogoss\OAuth\TokenException');
        $this->expectExceptionCode(TokenException::INVALID_TOKEN_STRUCT);

        OAuth::withSecret(self::SECRET)->LoadToken($sToken);
    }
}
