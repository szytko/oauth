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

namespace Vegas\Security;

use OAuth\Common\Consumer\Credentials;
use OAuth\Common\Http\Client\ClientInterface;
use OAuth\Common\Http\Client\CurlClient;
use OAuth\Common\Http\Uri\UriFactory;
use OAuth\Common\Storage\Memory;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\ServiceFactory;
use Vegas\Security\OAuth\Exception\InvalidApplicationKeyException;
use Vegas\Security\OAuth\Exception\InvalidApplicationSecretKeyException;
use Vegas\Security\OAuth\Exception\ServiceNotFoundException;
use Vegas\Security\OAuth\Exception\ServiceNotInitializedException;
use Vegas\Security\OAuth\ServiceDecorator;

/**
 * Class OAuth
 *
 * @package Vegas\Security
 */
class OAuth
{
    /**
     * @var TokenStorageInterface
     */
    protected $tokenStorage = null;

    /**
     * @var CurlClient
     */
    protected $httpClient = null;

    /**
     * @var \OAuth\Common\Http\Uri\UriInterface
     */
    protected $uriFactory;

    /**
     * @var array
     */
    protected $services = [];

    /**
     * @param \OAuth\Common\Storage\TokenStorageInterface $tokenStorage
     * @param ClientInterface $defaultHttpClient
     */
    public function __construct(TokenStorageInterface $tokenStorage = null, ClientInterface $defaultHttpClient = null)
    {
        if ($tokenStorage !== null) {
            $this->tokenStorage = $tokenStorage;
        } else {
            $this->tokenStorage = $this->getDefaultTokenStorage();
        }
        if ($defaultHttpClient !== null) {
            $this->httpClient = $defaultHttpClient;
        } else {
            $this->httpClient = $this->getDefaultHttpClient();
        }

        $uriFactory = new UriFactory();
        $this->uriFactory = $uriFactory->createFromSuperGlobalArray($_SERVER);
        $this->uriFactory->setQuery('');
    }

    /**
     * Creates service indicated by name using specified credentials and scopes
     *
     * @param $serviceName
     * @param array $credentials
     * @param array $scopes
     * @throws InvalidApplicationKeyException
     * @throws InvalidApplicationSecretKeyException
     * @throws ServiceNotFoundException
     * @return \Vegas\Security\OAuth\ServiceDecorator
     */
    public function createService($serviceName, array $credentials, array $scopes = [])
    {
        $serviceFactory = new ServiceFactory();
        $serviceFactory->setHttpClient($this->httpClient);
        $serviceInstance = $serviceFactory->createService(
            $serviceName,
            $this->createCredentials($credentials),
            $this->tokenStorage,
            $scopes
        );
        if (!$serviceInstance) {
            throw new ServiceNotFoundException($serviceName);
        }
        $decorator = new ServiceDecorator($serviceName, $serviceInstance, $this->tokenStorage);
        $this->services[$serviceName] = $decorator;

        return $decorator;
    }

    /**
     * Returns initialized service instance
     *
     * @param string $serviceName
     * @return \Vegas\Security\OAuth\ServiceDecorator
     * @throws ServiceNotInitializedException
     */
    public function getService($serviceName)
    {
        if (!isset($this->services[$serviceName]) || !$this->services[$serviceName] instanceof ServiceDecorator) {
            throw new ServiceNotInitializedException($serviceName);
        }

        return $this->services[$serviceName];
    }

    /**
     * Returns already initialized services
     *
     * @return array
     */
    public function getServices()
    {
        return $this->services;
    }

    /**
     * Setups provider credentials
     *
     * @param array $credentials
     * @return \OAuth\Common\Consumer\Credentials
     * @throws InvalidApplicationKeyException
     * @throws InvalidApplicationSecretKeyException
     */
    protected function createCredentials(array $credentials)
    {
        if (!array_key_exists('key', $credentials)) {
            throw new InvalidApplicationKeyException();
        }
        if (!array_key_exists('secret', $credentials)) {
            throw new InvalidApplicationSecretKeyException();
        }
        if (isset($credentials['redirect_uri'])) {
            $this->uriFactory->setPath($credentials['redirect_uri']);
        }
        return new Credentials(
            $credentials['key'],
            $credentials['secret'],
            $this->uriFactory->getAbsoluteUri()
        );
    }

    /**
     * Sets token storage
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
     * Returns token storage instance
     *
     * @return TokenStorageInterface
     */
    public function getTokenStorage()
    {
        return $this->tokenStorage;
    }

    /**
     * Returns default token storage instance
     *
     * @return TokenStorageInterface
     */
    public function getDefaultTokenStorage()
    {
        return new Memory();
    }

    /**
     * @param ClientInterface $client
     * @return $this
     */
    public function setHttpClient(ClientInterface $client)
    {
        $this->httpClient = $client;

        return $this;
    }

    /**
     * @return ClientInterface
     */
    public function getHttpClient()
    {
        return $this->httpClient;
    }

    /**
     * @return CurlClient
     */
    public function getDefaultHttpClient()
    {
        return new CurlClient();
    }
}