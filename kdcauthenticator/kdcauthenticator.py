#
# Copyright 2015-2017, Bloomberg Finance L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import kerberos

from tornado import gen, web
from jupyterhub.handlers import BaseHandler
from jupyterhub.auth import LocalAuthenticator
from jupyterhub.utils import url_path_join
from tornado import gen

from traitlets import (
    Any, Bool, Dict, Instance, Integer, Float, List, Unicode,
    validate,
)

class KDCLoginHandler(BaseHandler):
    """Basic handler for KDC Login. Calls authenticator to verify Kerberos credential."""
    
    scope = []

    @gen.coroutine
    def get(self):
        self.log.info("KDCLoginHandler get")
        redirect_uri = self.authenticator.callback_url(self.base_url)
        self.redirect(redirect_uri)

class KDCCallbackHandler(BaseHandler):
    """Basic handler for KDC callback. Calls authenticator to verify Kerberos credential."""

    def _unauthorized(self):
        '''
        Indicate that authentication is required
        '''
        self.log.info("unauthorized")
        self.set_status(401)
        self.set_header('WWW-Authenticate','Negotiate')
        self.finish()

    def _stop(self, username):
        self.log.info("stop")
        html = self._render(
            login_error='Invalid credential',
            username=username,
        )
        self.finish(html)

    def _forbidden(self):
        '''
        Indicate a complete authentication failure
        '''
        raise web.HTTPError(403)

    @gen.coroutine
    def get(self):

        header = self.request.headers.get("Authorization")
        self.log.info("Authorization Header " + str(header))
        if header:
            token = ''.join(header.split()[1:])
            result = yield self.authenticator.get_authenticated_user(self, token)
            self.log.info("result from get_authenticated_user " + str(result))
            username = None
            if not result:
                self._unauthorized()
                return
                
            if result and type(result) == dict:
                result = result['name']

            rc = None
            if ":" in result:
                rc, username = result.split(':')
            elif result != None:
                rc = result
            self.log.info("rc " + str(rc))
            if rc.upper() == "KERBEROS.AUTH_GSS_COMPLETE":
                self.log.info("kerberos.AUTH_GSS_COMPLETE: Username= " + username)
                if username:
                    userId = username.split("@")[0]
                    self.log.info("User = " + userId)
                    user = self.user_from_username(userId)
                    already_running = False
                    if user.spawner:
                        status = yield user.spawner.poll()
                        already_running = (status == None)
                    if not already_running and not user.spawner.options_form:
                        yield self.spawn_single_user(user)
                    self.set_login_cookie(user)
                    next_url = self.get_argument('next', default='')
                    if not next_url.startswith('/'):
                        next_url = ''
                    next_url = next_url or self.hub.server.base_url
                    self.redirect(next_url)
                    self.log.info("User logged in: %s", username)
                else:
                    self._stop(username)
            elif rc.upper() != "KERBEROS.AUTH_GSS_CONTINUE":
                self.log.info("Request forbidden")
                self._forbidden()
            else:
                self._unauthorized()
        else:
            self._unauthorized()

class KDCAuthenticator(LocalAuthenticator):
    """
    Kerberos Authenticator for JupyterHub
    """

#    service_name = Unicode('HTTP',
#                             help="This is a service principal"
#                             ).tag(config=True)
    service_name = 'HTTP'
    def callback_url(self, base_url):
        self.log.info("request callback_url " + base_url)
        return url_path_join(base_url, 'kdc_callback')

    def login_url(self, base_url):
        self.log.info("request login_url " + str(base_url))
        return url_path_join(base_url, 'kdc_login')

    login_handler = KDCLoginHandler
    callback_handler = KDCCallbackHandler

    def get_handlers(self, app):
        self.log.info("request get_handlers " + str(dir(app)))

        return [
            (r'/kdc_login', self.login_handler),
            (r'/login', self.login_handler),
            (r'/kdc_callback', self.callback_handler),
            (r'/callback', self.callback_handler)
        ]

    @gen.coroutine
    def authenticate(self, handler, data):
        '''
            Performs GSSAPI Negotiate Authentication
            @param token: GSSAPI Authentication Token
            @type token: str
            @returns gssapi return code or None on failure
            @rtype: int or None
            '''
        state = None
        try:
            self.log.info("try to authenticate to " + self.service_name)
            self.log.info("handler " + str(handler))
            self.log.info("data " + str(data))
            rc, state = kerberos.authGSSServerInit(self.service_name)
            self.log.info("kerberos.authGSSServerInit")
            if rc != kerberos.AUTH_GSS_COMPLETE:
                return None

            rc = kerberos.authGSSServerStep(state, data)
            self.log.info("kerberos.authGSSServerStep")
            if rc == kerberos.AUTH_GSS_COMPLETE:
                user = kerberos.authGSSServerUserName(state)
                self.log.info("Extracted User = " + user)
                return "kerberos.AUTH_GSS_COMPLETE:" + user
            elif rc == kerberos.AUTH_GSS_CONTINUE:
                return "kerberos.AUTH_GSS_CONTINUE"
            else:
                self.log.info("return None")
                return None
        except kerberos.GSSError as err:
            self.log.info("kerberos.GSSError: {0}".format(err))
            return None
        finally:
            if state:
                kerberos.authGSSServerClean(state)
