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

use OAuth\Common\Service\ServiceInterface;
use OAuth\Common\Storage\Exception\TokenNotFoundException;
use OAuth\Common\Storage\TokenStorageInterface;
use Vegas\Security\OAuth\Exception\FailedAuthorizationException;

/**
 * Class ServiceDecorator
 * @package Vegas\Security\OAuth
 */
class ServiceDecorator
{
    /**
     * Token storage instance
     *
     * @var TokenStorageInterface
     */
    protected $tokenStorage;

    /**
     * @var \OAuth\Common\Service\ServiceInterface
     */
    protected $service;

    /**
     * @var string
     */
    protected $serviceName;

    /**
     * Creates URI factory for building urls
     * Setups token storage
     * @param string $serviceName
     * @param ServiceInterface $service
     * @param TokenStorageInterface $tokenStorage
     */
    public function __construct($serviceName, ServiceInterface $service, TokenStorageInterface $tokenStorage)
    {
        $this->serviceName = $serviceName;
        $this->service = $service;
        $this->tokenStorage = $tokenStorage;
    }

    /**
     * @return string
     */
    public function getServiceName()
    {
        return $this->serviceName;
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
     * Authorization process
     *
     * @param $code
     * @param $state
     * @throws Exception\FailedAuthorizationException
     * @return \OAuth\Common\Http\Uri\UriInterface|boolean
     */
    public function authorize($code = null, $state = null)
    {
        try {
            if (!is_null($code)) {
                return $this->service->requestAccessToken($code, $state);
            }

            return false;
        } catch (\OAuth\Common\Exception\Exception $ex) {
            throw new FailedAuthorizationException($ex->getMessage());
        }
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
        $response = $this->service->request($path, $method, $body, $extraHeaders);
        return json_decode($response, true);
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