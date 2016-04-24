<?php
/***************************************************************************
 * Copyright (C) 1999-2012 Gadz.org                                        *
 * http://opensource.gadz.org/                                             *
 *                                                                         *
 * This program is free software; you can redistribute it and/or modify    *
 * it under the terms of the GNU General Public License as published by    *
 * the Free Software Foundation; either version 2 of the License, or       *
 * (at your option) any later version.                                     *
 *                                                                         *
 * This program is distributed in the hope that it will be useful,         *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of          *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the            *
 * GNU General Public License for more details.                            *
 *                                                                         *
 * You should have received a copy of the GNU General Public License       *
 * along with this program; if not, write to the Free Software             *
 * Foundation, Inc.,                                                       *
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA                   *
 ***************************************************************************/
namespace Gorg\Bundle\CasBundle\Security\Firewall;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Http\Firewall\AbstractAuthenticationListener;
use Symfony\Component\Security\Core\Role\Role;

/**
 * Class for wait the authentication event and call the CAS Api to throw the authentication process
 *
 * @category Authentication
 * @package  GorgCasBundle
 * @author   Mathieu GOULIN <mathieu.goulin@gadz.org>
 * @license  GNU General Public License
 */
class CasListener extends AbstractAuthenticationListener
{
    /**
     * {@inheritdoc}
     */
    protected function attemptAuthentication(Request $request)
    {
        /* Call CAS API to do authentication */
        \phpCAS::client($this->options['cas_protocol'], $this->options['cas_server'], $this->options['cas_port'], $this->options['cas_path'], false);

        if ($this->options['ca_cert_path']) {
            \phpCAS::setCasServerCACert($this->options['ca_cert_path']);
        } else {
            \phpCAS::setNoCasServerValidation();
        }
        \phpCAS::forceAuthentication();

        $user = null;
        $attributes = array();
        $roles = array(new Role('ROLE_USER'));
        // mapping cas attributes into user attributes
        if ($this->options['cas_mapping_attribute']) {
            $mapping = $this->options['cas_mapping_attribute'];
            $attributes = \phpCAS::getAttributes();

            // username
            if (in_array('username', $mapping, true) && in_array($mapping['username'], $attributes, true)) {
                $user = $attributes[$mapping['username']];
            }
            // roles
            if (array_key_exists('roles', $mapping) && array_key_exists($mapping['roles'], $attributes)) {
                $casRoles = explode(',', $attributes[$mapping['roles']]);
                $casRoles = array_map('trim', $casRoles);
                if ($this->options['cas_role_mapping']) {
                   // role mapping is defined in the config
                   foreach ($casRoles as $r) {
                       $mappedRole = array_key_exists($r, $this->options['cas_role_mapping']) ?
                           $this->options['cas_role_mapping'][$r] : $r;
                       $roles[] = new Role($mappedRole);
                   }
                }
            }
        }

        if (!$user) {
            // fall back to login name as username
            $user = \phpCAS::getUser();
        }

        if (null !== $this->logger) {
            $this->logger->info(sprintf('Authentication success: %s', $user));
        }

        return $this->authenticationManager->authenticate(new CasUserToken($user, $attributes, $roles));
    }
}
