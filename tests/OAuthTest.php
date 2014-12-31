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

namespace Vegas\Tests\Security;

use OAuth\Common\Http\Client\StreamClient;
use Phalcon\DI;
use Vegas\Security\OAuth;

class OAuthTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        parent::setUp();
        $_SERVER['REQUEST_URI'] = '/login';
    }

    public function testShouldCreateServiceByGivenName()
    {
        $oauth = new OAuth();

        $this->assertInstanceOf(
            '\Vegas\Security\OAuth\ServiceDecorator',
            $oauth->createService('linkedin', ['key' => 1, 'secret' => 1], [])
        );

        $this->assertInstanceOf(
            '\Vegas\Security\OAuth\ServiceDecorator',
            $oauth->createService('twitter', ['key' => 1, 'secret' => 1], [])
        );
    }

    public function testShouldThrowExceptionForInvalidServiceName()
    {
        $oauth = new OAuth();

        try {
            $oauth->createService('fake', ['key' => 1, 'secret' => 1], []);

            throw new \Exception();
        } catch (\Exception $e) {
            $this->assertInstanceOf('\Vegas\Security\OAuth\Exception\ServiceNotFoundException', $e);
        }
    }

    public function testShouldReturnDefaultTokenStorage()
    {
        $oauth = new OAuth();

        $this->assertInstanceOf('\OAuth\Common\Storage\Memory', $oauth->getDefaultTokenStorage());
        $this->assertInstanceOf('\OAuth\Common\Storage\Memory', $oauth->getTokenStorage());
    }

    public function testShouldChangeTokenStorage()
    {
        $oauth = new OAuth();
        $oauth->setTokenStorage(new OAuth\Storage\Session());

        $this->assertInstanceOf('\Vegas\Security\OAuth\Storage\Session', $oauth->getTokenStorage());
    }

    public function testShouldSetTokenStorageFromConstructor()
    {
        $oauth = new OAuth(new OAuth\Storage\Session());

        $this->assertInstanceOf('\Vegas\Security\OAuth\Storage\Session', $oauth->getTokenStorage());
    }

    public function testShouldReturnDefaultHttpClient()
    {
        $oauth = new OAuth();

        $this->assertInstanceOf('\OAuth\Common\Http\Client\CurlClient', $oauth->getDefaultHttpClient());
        $this->assertInstanceOf('\OAuth\Common\Http\Client\CurlClient', $oauth->getHttpClient());
    }

    public function testShouldChangeHttpClient()
    {
        $oauth = new OAuth();
        $oauth->setHttpClient(new \OAuth\Common\Http\Client\StreamClient());

        $this->assertInstanceOf('\OAuth\Common\Http\Client\StreamClient', $oauth->getHttpClient());
    }

    public function testShouldSetHttpClientFromConstructor()
    {
        $oauth = new OAuth(null, new StreamClient());

        $this->assertInstanceOf('\OAuth\Common\Http\Client\StreamClient', $oauth->getHttpClient());
    }

    public function testShouldThrowExceptionAboutInvalidApplicationKey()
    {
        $oauth = new OAuth();

        try {
            $oauth->createService('facebook', ['secret' => 1]);

            throw new \Exception();
        } catch (\Exception $e) {
            $this->assertInstanceOf('\Vegas\Security\OAuth\Exception\InvalidApplicationKeyException', $e);
        }
    }

    public function testShouldThrowExceptionAboutInvalidApplicationSecretKey()
    {
        $oauth = new OAuth();

        try {
            $oauth->createService('facebook', ['key' => 1]);

            throw new \Exception();
        } catch (\Exception $e) {
            $this->assertInstanceOf('\Vegas\Security\OAuth\Exception\InvalidApplicationSecretKeyException', $e);
        }
    }

    public function testShouldReturnAlreadyInitializedService()
    {
        $oauth = new OAuth();

        $this->assertInstanceOf(
            '\Vegas\Security\OAuth\ServiceDecorator',
            $oauth->createService('linkedin', ['key' => 1, 'secret' => 1], [])
        );
        $this->assertInstanceOf(
            '\Vegas\Security\OAuth\ServiceDecorator',
            $oauth->getService('linkedin')
        );
    }

    public function testShouldThrowExceptionWhenGettingNotInitializedService()
    {
        $oauth = new OAuth();

        $this->assertInstanceOf(
            '\Vegas\Security\OAuth\ServiceDecorator',
            $oauth->createService('linkedin', ['key' => 1, 'secret' => 1], [])
        );
        try {
            $oauth->getService('facebook');
        } catch (\Exception $e) {
            $this->assertInstanceOf('\Vegas\Security\OAuth\Exception\ServiceNotInitializedException', $e);
        }
    }

    public function testShouldSetRedirectUri()
    {
        $oauth = new OAuth();

        $service = $oauth->createService('google', ['key' => '1', 'secret' => '2', 'redirect_uri' => '/oauth/google'], []);
        $this->assertContains(urlencode('/oauth/google'), $service->getAuthorizationUri()->getQuery());
    }

    public function testShouldReturnArrayOfServices()
    {
        $oauth = new OAuth();

        $oauth->createService('google', ['key' => '1', 'secret' => '2'], []);
        $oauth->createService('facebook', ['key' => '1', 'secret' => '2'], []);

        $this->assertArrayHasKey('google', $oauth->getServices());
        $this->assertArrayHasKey('facebook', $oauth->getServices());
    }
} 