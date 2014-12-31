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

use OAuth\Common\Storage\Memory;
use OAuth\Common\Storage\TokenStorageInterface;
use Phalcon\DI\InjectionAwareInterface;
use Phalcon\DiInterface;
use Vegas\DI\InjectionAwareTrait;
use Vegas\Security\OAuth\Exception\ServiceNotFoundException;

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
     * @param \OAuth\Common\Storage\TokenStorageInterface $tokenStorage
     */
    public function __construct(TokenStorageInterface $tokenStorage = null)
    {
        if ($tokenStorage !== null) {
            $this->tokenStorage = $tokenStorage;
        } else {
            $this->tokenStorage = $this->getDefaultTokenStorage();
        }
    }

    /**
     * @param $adapterName
     * @param array $credentials
     * @param array $scopes
     * @throws OAuth\Exception\ServiceNotFoundException
     * @return OAuth\ServiceAbstract
     */
    public function obtainServiceInstance($adapterName, $credentials = [], $scopes = [])
    {
        $adapterNamespace = __NAMESPACE__ . '\OAuth\Service\\' . ucfirst($adapterName);
        try {
            $reflectionClass = new \ReflectionClass($adapterNamespace);
            $adapterInstance = $reflectionClass->newInstance(
                $this->tokenStorage, $credentials, $scopes
            );

            return $adapterInstance;
        } catch (\ReflectionException $ex) {
            throw new ServiceNotFoundException($adapterName);
        }
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
}