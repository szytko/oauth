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

use Vegas\Security\OAuth\Identity\Github;

class GithubTest extends \PHPUnit_Framework_TestCase
{
    public function testShouldReturnValidIdentity()
    {
        $mockData = [
            'email' => 'test@test.com',
            'id' => 1234,
            'name' => 'Name',
            'avatar_url' => 'picture.jpg',
            'html_url' => 'www.test.com'
        ];
        $mockBuilder = $this->getMockBuilder('\Vegas\Security\OAuth\ServiceDecorator');
        $mockBuilder->disableOriginalConstructor();
        $service = $mockBuilder->getMock();
        $service->expects($this->any())
            ->method('request')
            ->willReturn($mockData);

        $identity = new Github($service);
        $data = $identity->getIdentity();

        $this->assertEquals($data->email, $mockData['email']);
        $this->assertEquals($data->id, $mockData['id']);
        $this->assertEquals($data->firstName, $mockData['name']);
        $this->assertEquals($data->lastName, $mockData['name']);
        $this->assertEquals($data->picture, $mockData['avatar_url']);
        $this->assertEquals($data->link, $mockData['html_url']);
    }
} 