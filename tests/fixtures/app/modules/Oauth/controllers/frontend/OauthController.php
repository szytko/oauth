<?php
/**
 * This file is part of Vegas package
 *
 * @author Slawomir Zytko <slawomir.zytko@gmail.com>
 * @copyright Amsterdam Standard Sp. Z o.o.
 * @homepage https://bitbucket.org/amsdard/vegas-phalcon
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */
namespace Oauth\Controllers\Frontend;
use User\Services\Exception\SignUpFailedException;
use Vegas\Security\Authentication\Exception\IdentityNotFoundException;
use Vegas\Security\OAuth\Exception\FailedAuthorizationException;

/**
 * Class AuthController
 * @package Oauth\Controllers\Frontend
 */
class OauthController extends \Vegas\Mvc\Controller\ControllerAbstract
{
    private $oAuthService;

    public function initialize()
    {
        parent::initialize();

        $this->oAuthService = $this->serviceManager->get('oauth:oauth');
    }

    /**
     *
     */
    public function indexAction()
    {
        $this->view->linkedinUri = $this->oAuthService->getAuthorizationUri('linkedin');
        $this->view->facebookUri = $this->oAuthService->getAuthorizationUri('facebook');
        $this->view->googleUri = $this->oAuthService->getAuthorizationUri('google');
    }

    /**
     * @return \Phalcon\Http\ResponseInterface
     */
    public function authorizeAction()
    {
        $this->view->disable();

        $serviceName = $this->dispatcher->getParam('service');

        try {
            //authorize given service
            $this->oAuthService->authorize($serviceName, $this->request->getQuery('code'), $this->request->getQuery('state'));

            //

            return $this->response->redirect(array('for' => 'root'))->send();
        } catch(FailedAuthorizationException $ex) {
            $this->flashSession->message('error', $ex->getMessage());
            return $this->response->redirect(array('for' => 'login'))->send();
        }
    }

    /**
     * @return \Phalcon\Http\ResponseInterface
     */
    public function logoutAction()
    {
        $this->view->disable();
        $this->oAuthService->logout();

        return $this->response->redirect(array('for' => 'root'))->send();
    }
}
 
