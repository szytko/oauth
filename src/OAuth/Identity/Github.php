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

namespace Vegas\Security\OAuth\Service;

use Vegas\Security\OAuth\Identity;
use Vegas\Security\OAuth\ServiceAbstract;

class GitHub extends ServiceAbstract
{
    /**
     * Name of oAuth service
     */
    const SERVICE_NAME = 'GitHub';

    /**
     * Defined scopes, see http://developer.github.com/v3/oauth/ for definitions.
     */

    /**
     * Public read-only access (includes public user profile info, public repo info, and gists)
     */
    const SCOPE_READONLY = '';

    /**
     * Read/write access to profile info only.
     *
     * Includes SCOPE_USER_EMAIL and SCOPE_USER_FOLLOW.
     */
    const SCOPE_USER = 'user';

    /**
     * Read access to a user’s email addresses.
     */
    const SCOPE_USER_EMAIL = 'user:email';

    /**
     * Access to follow or unfollow other users.
     */
    const SCOPE_USER_FOLLOW = 'user:follow';

    /**
     * Read/write access to public repos and organizations.
     */
    const SCOPE_PUBLIC_REPO = 'public_repo';

    /**
     * Read/write access to public and private repos and organizations.
     *
     * Includes SCOPE_REPO_STATUS.
     */
    const SCOPE_REPO = 'repo';

    /**
     * Read/write access to public and private repository commit statuses. This scope is only necessary to grant other
     * users or services access to private repository commit statuses without granting access to the code. The repo and
     * public_repo scopes already include access to commit status for private and public repositories, respectively.
     */
    const SCOPE_REPO_STATUS = 'repo:status';

    /**
     * Delete access to adminable repositories.
     */
    const SCOPE_DELETE_REPO = 'delete_repo';

    /**
     * Read access to a user’s notifications. repo is accepted too.
     */
    const SCOPE_NOTIFICATIONS = 'notifications';

    /**
     * Write access to gists.
     */
    const SCOPE_GIST = 'gist';

    /**
     * Grants read and ping access to hooks in public or private repositories.
     */
    const SCOPE_HOOKS_READ = 'read:repo_hook';

    /**
     * Grants read, write, and ping access to hooks in public or private repositories.
     */
    const SCOPE_HOOKS_WRITE = 'write:repo_hook';

    /**
     * Grants read, write, ping, and delete access to hooks in public or private repositories.
     */
    const SCOPE_HOOKS_ADMIN = 'admin:repo_hook';

    /**
     * Returns the name of current service
     *
     * @return mixed
     */
    public function getServiceName()
    {
        return self::SERVICE_NAME;
    }

    /**
     * @return mixed
     */
    public function getIdentity()
    {
        $response = $this->request('user');
        $identity = new Identity($this->getServiceName(), $response['email']);
        $identity->id = $response['id'];
        $identity->firstName = $response['name'];
        $identity->lastName = $response['name'];
        $identity->picture = $response['avatar_url'];
        $identity->link = $response['html_url'];

        return $identity;
    }
}
 