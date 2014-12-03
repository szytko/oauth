<?php
/**
 * This file is part of Vegas package
 *
 * @author Slawomir Zytko <slawek@amsterdam-standard.pl>
 * @copyright Amsterdam Standard Sp. Z o.o.
 * @Testpage http://vegas-cmf.github.io
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */
 
namespace Home\Controllers\Frontend;

use Vegas\Mvc\Controller\ControllerAbstract;
use Vegas\Http\Response\Json as JsonResponse;

class HomeController extends ControllerAbstract
{
    public function indexAction()
    {
        echo 1;
    }

    public function loginAction()
    {

    }
} 