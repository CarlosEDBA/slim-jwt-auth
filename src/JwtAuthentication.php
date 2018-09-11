<?php

declare(strict_types=1);

/**
 * This file is part of PSR-7 & PSR-15 JWT Authentication middleware
 *
 * Copyright (c) 2015-2018 Mika Tuupola
 *
 * Licensed under the MIT license:
 *   http://www.opensource.org/licenses/mit-license.php
 *
 * Project home:
 *   https://github.com/tuupola/slim-jwt-auth
 *   https://appelsiini.net/projects/slim-jwt-auth
 *
 */

namespace Tuupola\Middleware;

use Closure;
use DomainException;
use Exception;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Keychain;
use Lcobucci\JWT\Signer\Hmac\Sha256 as HmacSha256;
use Lcobucci\JWT\Signer\Hmac\Sha384 as HmacSha384;
use Lcobucci\JWT\Signer\Hmac\Sha512 as HmacSha512;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RsaSha256;
use Lcobucci\JWT\Signer\Rsa\Sha384 as RsaSha384;
use Lcobucci\JWT\Signer\Rsa\Sha512 as RsaSha512;
use Lcobucci\JWT\Signer\Ecdsa\Sha256 as EcdsaSha256;
use Lcobucci\JWT\Signer\Ecdsa\Sha384 as EcdsaSha384;
use Lcobucci\JWT\Signer\Ecdsa\Sha512 as EcdsaSha512;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;
use RuntimeException;
use Tuupola\Middleware\DoublePassTrait;
use Tuupola\Http\Factory\ResponseFactory;
use Tuupola\Middleware\JwtAuthentication\RequestMethodRule;
use Tuupola\Middleware\JwtAuthentication\RequestPathRule;

final class JwtAuthentication implements MiddlewareInterface
{
  use DoublePassTrait;

  /**
   * PSR-3 compliant logger.
   */
  private $logger;

  /**
   * Last error message.
   */
  private $message;

  /**
   * The rules stack.
   */
  private $rules;

  /**
   * Stores all the options passed to the middleware.
   */
  private $options = [
    "secure" => true,
    "relaxed" => ["localhost", "127.0.0.1"],
    "algorithm" => ["HS256", "HS512", "HS384"],
    "header" => "Authorization",
    "regexp" => "/Bearer\s+(.*)$/i",
    "cookie" => "token",
    "attribute" => "token",
    "path" => null,
    "ignore" => null,
    "before" => null,
    "after" => null,
    "error" => null
  ];

  public function __construct(array $options = [])
  {
    /* Setup stack for rules */
    $this->rules = new \SplStack;

    /* Store passed in options overwriting any defaults. */
    $this->hydrate($options);

    /* If nothing was passed in options add default rules. */
    if (!isset($options["rules"])) {
      $this->rules->push(new RequestMethodRule([
        "ignore" => ["OPTIONS"]
      ]));
    }

    /* If path was given in easy mode add rule for it. */
    if (null !== ($this->options["path"])) {
      $this->rules->push(new RequestPathRule([
        "path" => $this->options["path"],
        "ignore" => $this->options["ignore"]
      ]));
    }
  }

  /**
   * Process a request in PSR-15 style and return a response.
   */
  public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
  {
    $scheme = $request->getUri()->getScheme();
    $host = $request->getUri()->getHost();

    /* If rules say we should not authenticate call next and return. */
    if (false === $this->shouldAuthenticate($request)) {
      return $handler->handle($request);
    }

    /* HTTP allowed only if secure is false or server is in relaxed array. */
    if ("https" !== $scheme && true === $this->options["secure"]) {
      if (!in_array($host, $this->options["relaxed"])) {
        $message = sprintf(
          "Insecure use of middleware over %s denied by configuration.",
          strtoupper($scheme)
        );
        throw new RuntimeException($message);
      }
    }

    /* If token cannot be found or decoded return with 401 Unauthorized. */
    try {
      $token = $this->fetchToken($request);
      //$decoded = $this->decodeToken($token);
    } catch (RuntimeException | DomainException $exception) {
      $response = (new ResponseFactory)->createResponse(401);
      return $this->processError($response, [
        "message" => $exception->getMessage()
      ]);
    }

    $params = ["decoded" => $decoded];

    /* Add decoded token to request as attribute when requested. */
    if ($this->options["attribute"]) {
      $request = $request->withAttribute($this->options["attribute"], $decoded);
    }

    /* Modify $request before calling next middleware. */
    if (is_callable($this->options["before"])) {
      $response = (new ResponseFactory)->createResponse(200);
      $beforeRequest = $this->options["before"]($request, $params);
      if ($beforeRequest instanceof ServerRequestInterface) {
        $request = $beforeRequest;
      }
    }

    /* Everything ok, call next middleware. */
    $response = $handler->handle($request);

    /* Modify $response before returning. */
    if (is_callable($this->options["after"])) {
      $afterResponse = $this->options["after"]($response, $params);
      if ($afterResponse instanceof ResponseInterface) {
        return $afterResponse;
      }
    }

    return $response;
  }

  /**
   * Set all rules in the stack.
   */
  public function withRules(array $rules): self
  {
    $new = clone $this;
    /* Clear the stack */
    unset($new->rules);
    $new->rules = new \SplStack;
    /* Add the rules */
    foreach ($rules as $callable) {
      $new = $new->addRule($callable);
    }
    return $new;
  }

  /**
   * Add a rule to the stack.
   */
  public function addRule(callable $callable): self
  {
    $new = clone $this;
    $new->rules = clone $this->rules;
    $new->rules->push($callable);
    return $new;
  }

  /**
   * Check if middleware should authenticate.
   */
  private function shouldAuthenticate(ServerRequestInterface $request): bool
  {
    /* If any of the rules in stack return false will not authenticate */
    foreach ($this->rules as $callable) {
      if (false === $callable($request)) {
        return false;
      }
    }
    return true;
  }

  /**
   * Call the error handler if it exists.
   */
  private function processError(ResponseInterface $response, array $arguments): ResponseInterface
  {
    if (is_callable($this->options["error"])) {
      $handlerResponse = $this->options["error"]($response, $arguments);
      if ($handlerResponse instanceof ResponseInterface) {
        return $handlerResponse;
      }
    }
    return $response;
  }

  /**
   * Fetch the access token.
   */
  private function fetchToken(ServerRequestInterface $request): string
  {
    $header = "";
    $message = "Using token from request header";

    /* Check for token in header. */
    $headers = $request->getHeader($this->options["header"]);
    $header = isset($headers[0]) ? $headers[0] : "";

    if (preg_match($this->options["regexp"], $header, $matches)) {
      $this->log(LogLevel::DEBUG, $message);
      return $matches[1];
    }

    /* Token not found in header try a cookie. */
    $cookieParams = $request->getCookieParams();

    if (isset($cookieParams[$this->options["cookie"]])) {
      $this->log(LogLevel::DEBUG, "Using token from cookie");
      $this->log(LogLevel::DEBUG, $cookieParams[$this->options["cookie"]]);
      return $cookieParams[$this->options["cookie"]];
    };

    /* If everything fails log and throw. */
    $this->log(LogLevel::WARNING, "Token not found");
    throw new RuntimeException("Token not found.");
  }

  /**
   * Decode the token.
   */
  private function decodeToken(string $token): array
  {
    try {
      $decoded = JWT::decode(
        $token,
        $this->options["secret"],
        (array) $this->options["algorithm"]
      );
      return (array) $decoded;
    } catch (Exception $exception) {
      $this->log(LogLevel::WARNING, $exception->getMessage(), [$token]);
      throw $exception;
    }
  }

  /**
   * Hydrate options from given array.
   */
  private function hydrate($data = []): void
  {
    foreach ($data as $key => $value) {
      /* https://github.com/facebook/hhvm/issues/6368 */
      $key = str_replace(".", " ", $key);
      $method = lcfirst(ucwords($key));
      $method = str_replace(" ", "", $method);
      if (method_exists($this, $method)) {
        /* Try to use setter */
        call_user_func([$this, $method], $value);
      } else {
        /* Or fallback to setting option directly */
        $this->options[$key] = $value;
      }
    }
  }

  /**
   * Set path where middleware should bind to.
   */
  private function path($path): void
  {
    $this->options["path"] = (array) $path;
  }

  /**
   * Set path which middleware ignores.
   */
  private function ignore($ignore): void
  {
    $this->options["ignore"] = (array) $ignore;
  }

  /**
   * Set the cookie name where to search the token from.
   */
  private function cookie($cookie): void
  {
    $this->options["cookie"] = $cookie;
  }

  /**
   * Set the secure flag.
   */
  private function secure(bool $secure): void
  {
    $this->options["secure"] = $secure;
  }

  /**
   * Set hosts where secure rule is relaxed.
   */
  private function relaxed(array $relaxed): void
  {
    $this->options["relaxed"] = $relaxed;
  }

  /**
   * Set the secret key.
   */
  private function secret(string $secret): void
  {
    $this->options["secret"] = $secret;
  }

  /**
   * Set the error handler.
   */
  private function error(Closure $error): void
  {
    $this->options["error"] = $error->bindTo($this);
  }

  /**
   * Set the logger.
   */
  private function logger(LoggerInterface $logger = null)
  {
    $this->logger = $logger;
  }

  /**
   * Logs with an arbitrary level.
   */
  private function log($level, string $message, array $context = []): void
  {
    if ($this->logger) {
      $this->logger->log($level, $message, $context);
    }
  }

  /**
   * Set the attribute name used to attach decoded token to request.
   */
  private function attribute(string $attribute): void
  {
    $this->options["attribute"] = $attribute;
  }

  /**
   * Set the header where token is searched from.
   */
  private function header(string $header): void
  {
    $this->options["header"] = $header;
  }

  /**
   * Set the regexp used to extract token from header or environment.
   */
  private function regexp(string $regexp): void
  {
    $this->options["regexp"] = $regexp;
  }

  /**
   * Set the allowed algorithms
   */
  private function algorithm($algorithm): void
  {
    $this->options["algorithm"] = (array) $algorithm;
  }

  /**
   * Set the before handler.
   */

  private function before(Closure $before): void
  {
    $this->options["before"] = $before->bindTo($this);
  }

  /**
   * Set the after handler.
   */
  private function after(Closure $after): void
  {
    $this->options["after"] = $after->bindTo($this);
  }

  /**
   * Set the rules.
   */
  private function rules(array $rules): void
  {
    $this->rules = $rules;
  }

  /**
   * Returns the right signer's instance
   *
   * @param string $signature
   * @param string $algorithm
   */
  public static function getSigner($signature = 'hmac', $algorithm = 'sha256')
  {
    if (strtolower($signature) == "hmac") {
      switch (strtolower($algorithm)) {
        case 'sha256':
          $signer = new HmacSha256();
          break;

        case 'sha384':
          $signer = new HmacSha384();
          break;

        case 'sha512':
          $signer = new HmacSha512();
          break;
        
        default:
          $signer = new HmacSha256();
          break;
      }

      return $signer;

    } else if (strtolower($signature) == "rsa") {
      switch (strtolower($algorithm)) {
        case 'sha256':
          $signer = new RsaSha256();
          break;

        case 'sha384':
          $signer = new RsaSha384();
          break;

        case 'sha512':
          $signer = new RsaSha512();
          break;

        default:
          $signer = new RsaSha256();
          break;
      }

      return $signer;
      
    } else if (strtolower($signature) == "ecdsa") {
      switch (strtolower($algorithm)) {
        case 'sha256':
          $signer = new EcdsaSha256();
          break;

        case 'sha384':
          $signer = new EcdsaSha384();
          break;

        case 'sha512':
          $signer = new EcdsaSha512();
          break;

        default:
          $signer = new EcdsaSha256();
          break;
      }

      return $signer;
      
    } else {
      throw new \Exception("Invalid signature.");
      return false;
    }
  }

  /**
   * Signs the token using Hmac and the selected algorithm
   *
   * @param Builder $builder
   * @param string $algorithm
   * @param string $key
   */
  public static function signWithHmac($builder, $algorithm = 'sha256', $key = '')
  {
    if (strlen($key) > 0) {
      $signer = self::getSigner('hmac', $algorithm);
      $token = $builder->sign($signer,  $key)->getToken();

      return $token;
    } else {
      throw new \Exception("Signing secret missing.");
      return false;
    }
  }

  /**
   * Signs the token using RSA and the selected algorithm
   *
   * @param Builder $builder
   * @param string $algorithm
   * @param string $key
   */
  public static function signWithRSA($builder, $algorithm = 'sha256', $key = '')
  {
    if (strlen($key) > 0) {
      $signer = self::getSigner('rsa', $algorithm);
      $keychain = new Keychain();
      $privateKey = $keychain->getPrivateKey("file://" . $key);

      $token = $builder->sign($signer,  $privateKey)->getToken();

      return $token;
    } else {
      throw new \Exception("Signing key not found.");
      return false;
    }
  }

  /**
   * Signs the token using RSA and the selected algorithm
   *
   * @param Builder $builder
   * @param string $algorithm
   * @param string $key
   */
  public static function signWithECDSA($builder, $algorithm = 'sha256', $key = '')
  {
    if (strlen($key) > 0) {
      $signer = self::getSigner('ecdsa', $algorithm);
      $keychain = new Keychain();
      $privateKey = $keychain->getPrivateKey("file://" . $key);

      $token = $builder->sign($signer,  $privateKey)->getToken();

      return $token;
    } else {
      throw new \Exception("Signing key not found.");
      return false;
    }
  }

  /**
   * Generate and return a signed token
   *
   * @param string $signature
   * @param string $algorithm
   * @param string $key
   * @param array $payload
   */
  public static function generate($signature = 'hmac', $algorithm = 'sha256', $key = '', $options = [], $payload = [])
  {
    $builder = new Builder();

    foreach ($options as $key => $value) {
      switch ($key) {
        case 'iss':
          if (!empty($value)) {
            $builder->setIssuer($value);
          }
          break
        case 'sub':
          break
        case 'exp':
          if (!empty($value)) {
            $builder->setExpiration($value);
          } else {
            $builder->setExpiration(time() + (7 * 24 * 60 * 60));
          }
          break
        case 'nbf':
          if (!empty($value)) {
            $builder->setNotBefore($value);
          } else {
            $builder->setNotBefore(time() + 10);
          }
          break
        case 'iat':
          if (!empty($value)) {
            $builder->setIssuedAt($value);
          } else {
            $builder->setIssuedAt(time());
          }
          break
        case 'jti':
          if (!empty($value)) {
            $builder->setId($value, true);
          } else {
            $builder->setId(IdGenerator::uniqueId(), true);
          }
          break
      }
    }

    if (count($payload)) {
      foreach ($payload as $key => $value) {
        $builder->set($key, $value);
      }
    }
        
    if (strtolower($signature) == "hmac") {
      return self::signWithHmac($builder, $algorithm, $key);
    } else if (strtolower($signature) == "rsa") {
      return self::signWithRSA($builder, $algorithm, $key);
    } else if (strtolower($signature) == "ecdsa") {
      return self::signWithECDSA($builder, $algorithm, $key);
    } else {
      throw new \Exception("Invalid signature.");
      return false;
    }
  }

  /**
   * Verifies if the token was modified after its generation.
   *
   * @param string $signature
   * @param string $algorithm
   * @param string $key
   * @param Token $token
   */
  public static function verify($signature = 'hmac', $algorithm = 'sha256', $key = '', $token)
  {
    if (is_string($token)) $token = (new Parser())->parse((string) $token);
    if ($token instanceof Token) {
      if (strtolower($signature) == "hmac") {
        $signer = self::getSigner($signature, $algorithm);

        return ($token->verify($signer, $key)) ? $token : false;
      } else if (strtolower($signature) == "rsa" || strtolower($signature) == "ecdsa") {
        $signer = self::getSigner($signature, $algorithm);

        $keychain = new Keychain();
        $publicKey = $keychain->getPublicKey("file://" . $key);

        return ($token->verify($signer, $publicKey)) ? $token : false;
      } else {
        throw new \Exception("Invalid signature.");
        return false;
      }
    }
  }
}
