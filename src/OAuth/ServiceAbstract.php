<?php
/**
 * This file is part of Vegas package
 *
 * @author Slawomir Zytko <slawek@amsterdam-standard.pl>
 * @copyright Amsterdam Standard Sp. Z o.o.
 * @homepage http://vegas-cmf.github.io
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Vegas\Security\OAuth;

use OAuth\Common\Consumer\Credentials;
use OAuth\Common\Http\Client\CurlClient;
use OAuth\Common\Storage\Exception\TokenNotFoundException;
use OAuth\Common\Storage\TokenStorageInterface;
use Vegas\DI\InjectionAwareTrait;
use Vegas\Security\OAuth\Exception\FailedAuthorizationException;
use Vegas\Security\OAuth\Exception\InvalidApplicationKeyException;
use Vegas\Security\OAuth\Exception\InvalidApplicationSecretKeyException;
use Vegas\Security\OAuth\Exception\ServiceNotInitializedException;

/**
 * Class AdapterAbstract
 * @package Vegas\Security\OAuth
 */
abstract class ServiceAbstract
{
    /**
     * URI helper
     *
     * @var \OAuth\Common\Http\Uri\UriInterface
     */
    protected $currentUri;

    /**
     * Token storage instance
     *
     * @var TokenStorageInterface
     */
    protected $tokenStorage;

    /**
     * Provided credentials
     *
     * @var Credentials
     */
    protected $credentials;

    /**
     * List of added providers scopes
     *
     * @var array
     */
    protected $scopes = array();

    /**
     * @var \OAuth\Common\Service\ServiceInterface
     */
    protected $service;

    /**
     * Creates URI factory for building urls
     * Setups token storage
     *
     * @param TokenStorageInterface $tokenStorage
     * @param array $credentials
     * @param array $scopes
     */
    public function __construct(TokenStorageInterface $tokenStorage, array $credentials, array $scopes = null)
    {
        $uriFactory = new \OAuth\Common\Http\Uri\UriFactory();
        $this->currentUri = $uriFactory->createFromSuperGlobalArray($_SERVER);
        $this->currentUri->setQuery('');

        //sets tokenStorage, credentials and scopes
        $this->tokenStorage = $tokenStorage;
        $this->setupCredentials($credentials);
        if ($scopes === null) {
            $this->setAllScopes();
        } else {
            $this->setScopes($scopes);
        }

        $this->service = $this->createService();
    }

    /**
     * Sets token storage instance
     *
     * @param TokenStorageInterface $tokenStorage
     * @return $this
     */
    public function setTokenStorage(TokenStorageInterface $tokenStorage)
    {
        $this->tokenStorage = $tokenStorage;

        return $this;
    }

    /**
     * Returns access token for current service
     *
     * @return \OAuth\Common\Token\TokenInterface
     */
    public function getAccessToken()
    {
        return $this->tokenStorage->retrieveAccessToken($this->getServiceName());
    }

    /**
     * Returns authorization state for current service
     *
     * @return string
     */
    public function getAuthorizationState()
    {
        return $this->tokenStorage->retrieveAuthorizationState($this->getServiceName());
    }

    /**
     * Returns the name of current service
     *
     * @return mixed
     */
    abstract public function getServiceName();

    /**
     * Returns identity object
     *
     * @return mixed
     */
    abstract public function getIdentity();

    /**
     * Authorization process
     *
     * @param $code
     * @param $state
     * @throws Exception\FailedAuthorizationException
     * @return \OAuth\Common\Http\Uri\UriInterface|string
     */
    public function authorize($code = null, $state = null)
    {
        $this->assertServiceInstance();

        try {
            if (!is_null($code)) {
                return $this->service->requestAccessToken($code, $state);
            }
        } catch (\OAuth\Common\Exception\Exception $ex) {
            throw new FailedAuthorizationException($ex->getMessage());
        }
    }

    /**
     * Setups provider credentials
     *
     * @param array $credentials
     * @throws Exception\InvalidApplicationKeyException
     * @throws Exception\InvalidApplicationSecretKeyException
     */
    public function setupCredentials(array $credentials)
    {
        if (!array_key_exists('key', $credentials)) {
            throw new InvalidApplicationKeyException();
        }
        if (!array_key_exists('secret', $credentials)) {
            throw new InvalidApplicationSecretKeyException();
        }
        if (isset($credentials['redirect_uri'])) {
            $this->currentUri->setPath($credentials['redirect_uri']);
        }
        $this->credentials = new Credentials(
            $credentials['key'],
            $credentials['secret'],
            $this->getCurrentAbsoluteUri()
        );
    }

    /**
     * Builds the full URI based on all the properties
     *
     * @return string
     */
    public function getCurrentAbsoluteUri()
    {
        return $this->currentUri->getAbsoluteUri();
    }

    /**
     * Sets all permissions, which user will be asked for during authorization process
     */
    public function setAllScopes()
    {
        $scopes = array();
        $reflectionClass = new \ReflectionClass(__CLASS__);
        foreach ($reflectionClass->getConstants() as $constantName => $constantValue) {
            if (strpos($constantName, 'SCOPE_') !== false) {
                $scopes = $constantValue;
            }
        }

        $this->setScopes($scopes);
    }

    /**
     * Sets provider scopes
     *
     * @param array $scopes
     * @return $this
     */
    public function setScopes(array $scopes = array())
    {
        $this->scopes = $scopes;

        return $this;
    }

    /**
     * Initializes the OAuth service
     * The service is created by \OAuth\ServiceFactory based upon
     * service name returned from getServiceName() method
     *
     * @return $this
     */
    public function createService()
    {
        $serviceFactory = new \OAuth\ServiceFactory();
        $serviceFactory->setHttpClient(new CurlClient());//set client
        $service = $serviceFactory->createService(
            $this->getServiceName(),
            $this->credentials,
            $this->tokenStorage,
            $this->scopes
        );

        return $service;
    }

    /**
     * Calls indicated method on OAuth service
     *
     * @param $name
     * @param $args
     * @return mixed
     */
    public function __call($name, $args)
    {
        $this->assertServiceInstance();

        return call_user_func(array($this->service, $name), $args);
    }

    /**
     * Sends an authenticated API request to the path provided.
     * If the path provided is not an absolute URI, the base API Uri (service-specific) will be used.
     *
     * @param string|UriInterface $path
     * @param string              $method       HTTP method
     * @param array               $body         Request body if applicable (an associative array will
     *                                          automatically be converted into a urlencoded body)
     * @param array               $extraHeaders Extra headers if applicable. These will override service-specific
     *                                          any defaults.
     *
     * @return array                            Decoded response
     */
    public function request($path, $method = 'GET', $body = null, array $extraHeaders = array())
    {
        $this->assertServiceInstance();

        $response = $this->service->request($path, $method, $body, $extraHeaders);
        return json_decode($response, true);
    }

    /**
     * Determines if OAuth service is initialized
     *
     * @return bool
     * @throws Exception\ServiceNotInitializedException
     */
    protected function assertServiceInstance()
    {
        if (!$this->service instanceof \OAuth\Common\Service\ServiceInterface) {
            throw new ServiceNotInitializedException();
        }

        return true;
    }

    /**
     * Obtains authentication for current service
     *
     * @return bool
     */
    public function isAuthenticated()
    {
        try {
            $token = $this->tokenStorage->retrieveAccessToken($this->getServiceName());
            if (!$token) {
                return false;
            }
            return $token->getEndOfLife() > time();
        } catch (TokenNotFoundException $e) {
            return false;
        }
    }

    /**
     * Cleans up
     *
     * @return $this
     */
    public function gc()
    {
        $this->tokenStorage->clearToken($this->getServiceName());
        $this->tokenStorage->clearAuthorizationState($this->getServiceName());

        return $this;
    }
} 