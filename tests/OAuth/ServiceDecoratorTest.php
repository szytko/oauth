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

namespace Vegas\Tests\Security\OAuth;

use OAuth\Common\Consumer\Credentials;
use OAuth\Common\Http\Client\CurlClient;
use OAuth\Common\Storage\Exception\TokenNotFoundException;
use Vegas\Security\OAuth;
use Vegas\Security\OAuth\ServiceDecorator;

class ServiceDecoratorTest extends \PHPUnit_Framework_TestCase
{
    private $tokenTime;

    protected function setUp()
    {
        $this->tokenTime = time() + 1000;
    }

    protected function mockToken()
    {
        $tokenMock = $this->getMock('\OAuth\Common\Token\AbstractToken');
        $tokenMock->expects($this->any())
            ->method('getEndOfLife')
            ->willReturn($this->tokenTime);

        return $tokenMock;
    }

    protected function mockTokenStorage()
    {
        $tokenStorageMock = $this->getMock('\OAuth\Common\Storage\Memory');
        $tokenStorageMock->expects($this->any())
            ->method('retrieveAccessToken')
            ->willReturn($this->mockToken());

        $tokenStorageMock->expects($this->any())
            ->method('retrieveAuthorizationState')
            ->willReturn(true);

        return $tokenStorageMock;
    }

    protected function mockService($tokenStorage)
    {
        $serviceMockBuilder = $this->getMockBuilder('\OAuth\OAuth2\Service\AbstractService');
        $serviceMockBuilder->setConstructorArgs([
            new Credentials('1', '2', 'www.test.com'),
            new CurlClient(),
            $tokenStorage
        ]);
        $serviceMockBuilder->setMethods([
            'requestAccessToken',
            'request',
            'parseAccessTokenResponse',
            'getAuthorizationEndpoint',
            'getAccessTokenEndpoint',
            'hasAuthorizationState'
        ]);

        $serviceMock = $serviceMockBuilder->getMock();
        $serviceMock->expects($this->any())
            ->method('requestAccessToken')
            ->will($this->returnValue('12'));

        $serviceMock->expects($this->any())
            ->method('request')
            ->willReturn(json_encode(['status' => 'OK']));

        $serviceMock->expects($this->any())
            ->method('parseAccessTokenResponse')
            ->willReturn($this->mockToken());

        $serviceMock->expects($this->any())
            ->method('getAuthorizationEndpoint')
            ->willReturn('authEndpoint');

        $serviceMock->expects($this->any())
            ->method('getAccessTokenEndpoint')
            ->willReturn('tokenEndpoint');

        return $serviceMock;
    }

    protected function createDecorator()
    {
        $tokenStorage = $this->mockTokenStorage();
        $serviceDecorator = new ServiceDecorator('test', $this->mockService($tokenStorage), $tokenStorage);
        return $serviceDecorator;
    }

    public function testShouldAuthorizeUsingGivenCodeAndState()
    {
        $decorator = $this->createDecorator();
        $this->assertEquals('12', $decorator->authorize(1, 2));
    }

    public function testShouldValidateToken()
    {
        $decorator = $this->createDecorator();
        $this->assertTrue($decorator->isAuthenticated());
    }

    public function testShouldReturnValidToken()
    {
        $decorator = $this->createDecorator();
        $this->assertSame($decorator->getAccessToken()->getEndOfLife(), $this->tokenTime);
    }

    public function testShouldReturnValidAuthorizationState()
    {
        $decorator = $this->createDecorator();
        $this->assertTrue($decorator->getAuthorizationState());
    }

    public function testShouldSendRequest()
    {
        $decorator = $this->createDecorator();
        $response = $decorator->request('/user');
        $this->assertSame(['status' => 'OK'], $response);
    }

    public function testShouldRemoveToken()
    {
        $decorator = $this->createDecorator();
        $decorator->gc();

        $this->assertNull($decorator->hasAuthorizationState());
        $this->assertNull($decorator->getAccessToken()->getAccessToken());
    }

    public function testShouldReturnFalseWhenTokenNotFound()
    {
        $tokenStorageMock = $this->getMock('\OAuth\Common\Storage\Memory');
        $tokenStorageMock->expects($this->any())
            ->method('retrieveAccessToken')
            ->willThrowException(new \OAuth\Common\Storage\Exception\TokenNotFoundException());

        $tokenStorageMock->expects($this->any())
            ->method('retrieveAuthorizationState')
            ->willReturn(true);

        $serviceMock = $this->mockService($tokenStorageMock);
        $serviceDecorator = new ServiceDecorator('test', $serviceMock, $tokenStorageMock);

        $this->assertFalse($serviceDecorator->isAuthenticated());
    }

    public function testShouldThrowExceptionForInvalidAuth()
    {
        $mockClient = $this->getMock('\OAuth\Common\Http\Client\CurlClient');
        $mockClient->expects($this->any())
            ->method('retrieveResponse')
            ->willThrowException(new TokenNotFoundException());

        $_SERVER['REQUEST_URI'] = '/login';

        $oauth = new OAuth($this->mockTokenStorage(), $mockClient);
        $service = $oauth->createService('google', ['key' => 1, 'secret' => 2], []);
        try {
            $service->authorize(1, true);

            throw new \Exception();
        } catch (\Exception $e) {
            $this->assertInstanceOf('\Vegas\Security\OAuth\Exception\FailedAuthorizationException', $e);
        }
    }

    public function testShouldReturnFalseForEmptyAuthorizationCode()
    {
        $decorator = $this->createDecorator();
        $this->assertFalse($decorator->authorize(null, true));
    }
} 