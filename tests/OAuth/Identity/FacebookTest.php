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

namespace Vegas\Tests\Security\OAuth\Identity;

use Vegas\Security\OAuth\Identity\Facebook;

class FacebookTest extends \PHPUnit_Framework_TestCase
{
    public function testShouldReturnValidIdentity()
    {
        $mockData = [
            'email' => 'test@test.com',
            'id' => 1234,
            'first_name' => 'First',
            'last_name' => 'Last',
            'picture' => ['data' => ['url' => 'picture.jpg']],
            'link' => 'www.test.com'
        ];

        $mockBuilder = $this->getMockBuilder('\Vegas\Security\OAuth\ServiceDecorator');
        $mockBuilder->disableOriginalConstructor();
        $service = $mockBuilder->getMock();
        $service->expects($this->any())
            ->method('request')
            ->willReturn($mockData);

        $identity = new Facebook($service);
        $data = $identity->getIdentity();

        $this->assertEquals($data->email, $mockData['email']);
        $this->assertEquals($data->id, $mockData['id']);
        $this->assertEquals($data->firstName, $mockData['first_name']);
        $this->assertEquals($data->lastName, $mockData['last_name']);
        $this->assertEquals($data->picture, $mockData['picture']['data']['url']);
        $this->assertEquals($data->link, $mockData['link']);
    }
} 