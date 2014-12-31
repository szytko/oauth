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

namespace Vegas\Security\OAuth\Identity;

use Vegas\Security\OAuth\Identity;
use Vegas\Security\OAuth\ServiceAbstract;
use Vegas\Security\OAuth\ServiceDecorator;

/**
 * Class GitHub
 * @package Vegas\Security\OAuth\Identity
 */
class Github
{
    /**
     * @var ServiceDecorator
     */
    protected $service;

    /**
     * @param ServiceDecorator $service
     */
    public function __construct(ServiceDecorator $service)
    {
        $this->service = $service;
    }

    /**
     * Returns the name of current service
     *
     * @return mixed
     */
    public function getServiceName()
    {
        return 'github';
    }

    /**
     * @return mixed
     */
    public function getIdentity()
    {
        $response = $this->service->request('user');
        $identity = new Identity($this->getServiceName(), $response['email']);
        $identity->id = $response['id'];
        $identity->firstName = $response['name'];
        $identity->lastName = $response['name'];
        $identity->picture = $response['avatar_url'];
        $identity->link = $response['html_url'];

        return $identity;
    }
}
 