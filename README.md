# PHP-OAuth

A a small library providing OAuth-Token generation and validation in an easy to use package.

The Tokens are signed via a `sha256 - Hash` and and User-Provideable Salt / Secret.

## How to use it?

1. Download the contents of the `lib/rogoss/OAuth` folder into your project.
   You can use the download of the Release - Section or just clone this Repo.

2. load the `rogoss\OAuth` class into your project

```php
<?php
    require_once __DIR__ . "/lib/rogoss/OAuth/OAuth.php";

    $oOAuth = \rogoss\OAuth\OAuth::withSecret(MYSECRET_PROVIDED_FROM_SOMEWHERE_ELSE);

/* alternativerly

    $oOAuth = \rogoss\OAuth\OAuth::blank();

    if you don't want to use a salt for some reason.
    Not sure, why you would do such a thing, though, but I'm not responsible for your code ;-)
*/

```

## Generating a new Token.

In order for someone to Authenticate with a Token, you must first generate one.

```php
<?php
    require_once __DIR__ . "/lib/rogoss/OAuth/OAuth.php";

    use \rogoss\OAuth\OAuth;

    $sToken = OAuth::withSecret(getenv("PHP_OAUTH_SECRET")) // Initialize OAuth
        ->NewToken()                                    // Tell it to generate a new Token
        ->setAgent($_SERVER['HTTP_USER_AGENT'])         // Optional: this token is limited to the agent it was created with
        ->setTTL(3600)                                  // Optional: Token is only valid for the next 3600 seconds (aka. an hour)
        ->setContent("A,B")                             // Optional: Content that can be retreived uppon reading the token
        ->finalize(true)                                // Sign the Token and return it as a Base64 String.
    ;

```

> [!note]
> note how all the functions belong to one command.
> I decided to use the Builder pattern to give you more flexibility in how you want to generate (or later validate) your Token

If your Token has no time restriction or an Agent, just leave out the functions for that, during the construction.

```php
<?php
    $sToken = OAuth::withSecret(getenv("PHP_OAUTH_SECRET")) // Initialize OAuth
        ->NewToken()                                    // Tell it to generate a new Token
        ->setContent("A,B")                             // Optional: Content that can be retreived uppon reading the token
        ->finalize(true)                                // Sign the Token and return it as a Base64 String.
    ;
```

## Validating a Token

It is almost as simple as generating one.

```php
<?php

    $sToken = "a token you received from somewhere else (like a header or a Bearer Token)";
    // In this case we'll validate the token we got from the previous section.

    use \rogoss\OAuth\OAuth;
    use \rogoss\OAuth\TokenException;

    try {

        $oToken = OAuth::withSecret(getenv("PHP_OAUTH_SECRET")) // Initialize OAuth
           ->LoadToken($sToken, true)                       // Tell it to validate an existing token (in this case the Base64 Token from the previous section)
           ->requiresAgent($_SERVER['HTTP_USER_AGENT'])     // Make sure the token was generated for the User-Agent of the current call
           ->requiresNoneExpired()                          // Make sure the token didn't reach its end of life
        ;

        $sTokenContent = $oToken->getContent(); // Retreive the Content.

        // From here, you can do further checks on the tokens content, etc.
        // For example. the countent could be a list of Rules or Perfmission Flags, etc.
        // ...

    } catch(TokenException $ex) {
        // You could check $ex to see what is wrong, but for this current case all we care about is if the token is valid.
        echo "invalid Token";
        exit;
    }
```

> [!note]
> once again, this uses the Builder-Pattern, so you can easy define what part of the validation you want to include

## Possible Exceptions

should something go wrong, OAuth will always throw a `\rogoss\OAuth\TokenException`.
The Exceptions Code can then tell you what went wrong.

| Error-Code | Constant                             | Meaning                                                                |
| ---------- | ------------------------------------ | ---------------------------------------------------------------------- |
| 1          | TokenException::SECRET_TO_SHORT      | The Given Secret was to short (must be at least 10 characters)         |
| 2          | TokenException::VALUE_NOT_JSON       | The Token that was received does not seem to be a valid JSON-Structure |
| 3          | TokenException::INVALID_TOKEN_STRUCT | The Tokens JSON-Structure misses fields or contains unexpected content |
| 4          | TokenException::VALUE_NOT_NUMMERIC   | A value was expected to be numeric, but it was not                     |
| 5          | TokenException::VALUE_EMPTY          | A value was expected to contain a none empty value but it did          |
| 6          | TokenException::VALUE_NOT_HASH       | A Value was expected to be a Hex-String, but it was not                |
| 7          | TokenException::AGENT_MISSMATCH      | The Tokens Agent did not match the required one                        |
| 8          | TokenException::TOKEN_EXPIRED        | The Tokens has expired                                                 |


