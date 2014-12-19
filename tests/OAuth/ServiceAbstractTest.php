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

class ServiceAbstractTest extends \PHPUnit_Framework_TestCase
{

    public function testShouldAuthorizeUsingGivenService()
    {
        $tokenStorage = $this->getMock('\OAuth\Common\Storage\Memory');
        $tokenStorage->expects($this->any())
            ->method('retrieveAccessToken')
            ->willReturn('accessToken');
        $tokenStorage->expects($this->any())
            ->method('retrieveAuthorizationState')
            ->willReturn('state');

        $tokenStorage->expects($this->any())
            ->method('clearToken')
            ->willReturnSelf();

        $tokenStorage->expects($this->any())
            ->method('clearAuthorizationState')
            ->willReturnSelf();

        $service = $this->getMockForAbstractClass('\Vegas\Security\OAuth\Service\Google');

    }

}
 