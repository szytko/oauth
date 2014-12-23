<?php
/**
 * This file is part of Vegas package
 *
 * @author Slawomir Zytko <slawomir.zytko@gmail.com>
 * @copyright Amsterdam Standard Sp. Z o.o.
 * @homepage http://vegas-cmf.github.io
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Vegas\Tests\Security\OAuth\Storage;

use Vegas\Security\OAuth\Storage\Session;

class SessionTest extends \PHPUnit_Framework_TestCase
{

    protected function mockToken()
    {
        $tokenMock = $this->getMock('\OAuth\Common\Token\AbstractToken');
        $tokenMock->expects($this->any())
            ->method('getEndOfLife')
            ->willReturn(time() - mt_rand());

        return $tokenMock;
    }

    public function testShouldStoreAccessTokenForEachService()
    {
        $session = new Session();

        $serviceToken = $this->mockToken();
        $service2Token = $this->mockToken();

        $session->storeAccessToken('test', $serviceToken);
        $session->storeAccessToken('test2', $service2Token);

        $this->assertTrue($session->hasAccessToken('test'));
        $this->assertTrue($session->hasAccessToken('test2'));

        $this->assertSame(
            $serviceToken->getEndOfLife(),
            $session->retrieveAccessToken('test')->getEndOfLife()
        );
        $this->assertSame(
            $service2Token->getEndOfLife(),
            $session->retrieveAccessToken('test2')->getEndOfLife()
        );

        $this->assertNotSame(
            $service2Token->getEndOfLife(),
            $session->retrieveAccessToken('test')->getEndOfLife()
        );

        $this->assertNotSame(
            $serviceToken->getEndOfLife(),
            $session->retrieveAccessToken('test2')->getEndOfLife()
        );
    }

    public function testShouldRemoveTokenForIndicatedService()
    {
        $session = new Session();

        $serviceToken = $this->mockToken();
        $service2Token = $this->mockToken();

        $session->storeAccessToken('test', $serviceToken);
        $session->storeAccessToken('test2', $service2Token);

        $session->clearToken('test');
        $this->assertFalse($session->hasAccessToken('test'));
        $this->assertTrue($session->hasAccessToken('test2'));

        $session->clearToken('test2');
        $this->assertFalse($session->hasAccessToken('test2'));
    }

    public function testShouldRemoveAllTokens()
    {
        $session = new Session();

        $serviceToken = $this->mockToken();
        $service2Token = $this->mockToken();

        $session->storeAccessToken('test', $serviceToken);
        $session->storeAccessToken('test2', $service2Token);

        $session->clearAllTokens();

        $this->assertFalse($session->hasAccessToken('test2'));
        $this->assertFalse($session->hasAccessToken('test2'));
    }

    public function testShouldThrowExceptionAboutMissingToken()
    {
        $session = new Session();
        try {
            $session->retrieveAccessToken('test');

            throw new \Exception();
        } catch (\Exception $e) {
            $this->assertInstanceOf('\OAuth\Common\Storage\Exception\TokenNotFoundException', $e);
        }
    }

    public function testShouldStoreAuthStateForEachService()
    {
        $session = new Session();

        $state = uniqid();
        $state2 = uniqid();

        $session->storeAuthorizationState('test', $state);
        $session->storeAuthorizationState('test2', $state2);

        $this->assertTrue($session->hasAuthorizationState('test'));
        $this->assertTrue($session->hasAuthorizationState('test2'));

        $this->assertSame(
            $state,
            $session->retrieveAuthorizationState('test')
        );
        $this->assertSame(
            $state2,
            $session->retrieveAuthorizationState('test2')
        );

        $this->assertNotSame(
            $state2,
            $session->retrieveAuthorizationState('test')
        );

        $this->assertNotSame(
            $state,
            $session->retrieveAuthorizationState('test2')
        );
    }

    public function testShouldRemoveAuthStateForIndicatedService()
    {
        $session = new Session();

        $state = uniqid();
        $state2 = uniqid();

        $session->storeAuthorizationState('test', $state);
        $session->storeAuthorizationState('test2', $state2);

        $session->clearAuthorizationState('test');
        $this->assertFalse($session->hasAuthorizationState('test'));
        $this->assertTrue($session->hasAuthorizationState('test2'));

        $session->clearAuthorizationState('test2');
        $this->assertFalse($session->hasAuthorizationState('test2'));
    }

    public function testShouldRemoveAllAuthStates()
    {
        $session = new Session();

        $state = uniqid();
        $state2 = uniqid();

        $session->storeAuthorizationState('test', $state);
        $session->storeAuthorizationState('test2', $state2);

        $session->clearAllAuthorizationStates();

        $this->assertFalse($session->hasAuthorizationState('test2'));
        $this->assertFalse($session->hasAuthorizationState('test2'));
    }

    public function testShouldThrowExceptionAboutMissingAuthState()
    {
        $session = new Session();
        try {
            $session->retrieveAuthorizationState('test');

            throw new \Exception();
        } catch (\Exception $e) {
            $this->assertInstanceOf('\OAuth\Common\Storage\Exception\AuthorizationStateNotFoundException', $e);
        }
    }
}