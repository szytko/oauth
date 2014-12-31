<?php
/**
 * This file is part of Vegas package
 *
 * @author Sławomir Żytko <slawek@amsterdam-standard.pl>
 * @copyright Amsterdam Standard Sp. Z o.o.
 * @homepage https://github.com/vegas-cmf
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Oauth\Services;

use OAuth\Common\Http\Client\CurlClient;
use Vegas\Security\OAuth\Identity as OAuthIdentity;
use Vegas\Security\OAuth\Identity;
use Vegas\Security\OAuth\ServiceAbstract;
use Vegas\Security\OAuth\Storage\Session;

/**
 * Class Oauth
 * @package Oauth\Services
 */
class Oauth implements \Phalcon\DI\InjectionAwareInterface
{
    use \Vegas\DI\InjectionAwareTrait;

    /**
     * @var array
     */
    protected $config = [];

    /**
     * @var \Vegas\Security\OAuth
     */
    protected $oAuth = null;

    /**
     * Initializes service from provided configuration
     *
     * @param null|array $config
     * @return $this
     */
    public function initialize($config = null)
    {
        if (null == $config) {
            $this->config = $this->getDI()->get('config')->oauth->toArray();
        } else {
            $this->config = $config;
        }
        $this->setupServices();

        return $this;
    }

    /**
     * Setups oAuth services from configuration
     */
    protected function setupServices()
    {
        $tokenStorage = new Session();
        $httpClient = new CurlClient();

        $this->oAuth = new \Vegas\Security\OAuth($tokenStorage, $httpClient);
        foreach ($this->config as $serviceName => $serviceConfig) {
            $this->oAuth->createService($serviceName, [
                    'key'   =>  $serviceConfig['key'],
                    'secret'    =>  $serviceConfig['secret'],
                    'redirect_uri'  =>  $serviceConfig['redirect_uri']
                ],
                isset($serviceConfig['scopes']) ? $serviceConfig['scopes'] : []
            );
        }
    }

    /**
     * Returns the instance of indicated service
     *
     * @param $serviceName
     * @return ServiceAbstract
     * @throws \Vegas\Security\OAuth\Exception\ServiceNotFoundException
     */
    public function getService($serviceName)
    {
        return $this->oAuth->getService($serviceName);
    }

    /**
     * Returns the prepared authorization uri to indicated oAuth Service
     *
     * @param $serviceName
     * @return mixed
     */
    public function getAuthorizationUri($serviceName)
    {
        return $this->getService($serviceName)->getAuthorizationUri();
    }

    /**
     * Authorizes indicated service
     *
     * @param $serviceName
     * @param $code
     * @param $state
     * @return \OAuth\Common\Http\Uri\UriInterface|string
     */
    public function authorize($serviceName, $code, $state)
    {
        return $this->getService($serviceName)->authorize($code, $state);
    }

    /**
     * Removes session for indicated service
     *
     * @param null $serviceName
     */
    public function logout($serviceName = null)
    {
        if (null == $serviceName) {
            foreach ($this->oAuth->getServices() as $serviceName => $service) {
                $service->gc();
            }
        } else {
            $this->getService($serviceName)->gc();
        }
    }
}
