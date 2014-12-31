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

use Vegas\Security\OAuth\Identity\Google;

class GoogleTest extends \PHPUnit_Framework_TestCase
{
    public function testShouldReturnValidIdentity()
    {
        $mockData = [
            'email' => 'test@test.com',
            'id' => 1234,
            'given_name' => 'First',
            'family_name' => 'Last',
            'picture' => 'picture.jpg',
            'link' => 'www.test.com'
        ];

        $mockBuilder = $this->getMockBuilder('\Vegas\Security\OAuth\ServiceDecorator');
        $mockBuilder->disableOriginalConstructor();
        $service = $mockBuilder->getMock();
        $service->expects($this->any())
            ->method('request')
            ->willReturn($mockData);

        $identity = new Google($service);
        $data = $identity->getIdentity();

        $this->assertEquals($data->email, $mockData['email']);
        $this->assertEquals($data->id, $mockData['id']);
        $this->assertEquals($data->firstName, $mockData['given_name']);
        $this->assertEquals($data->lastName, $mockData['family_name']);
        $this->assertEquals($data->picture, $mockData['picture']);
        $this->assertEquals($data->link, $mockData['link']);
    }
} 