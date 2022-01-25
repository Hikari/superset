import uuid

import requests
from flask import redirect, g, flash, request
from flask_appbuilder._compat import as_unicode
from flask_appbuilder.security.forms import LoginForm_db
from flask_appbuilder.security.views import UserDBModelView, AuthDBView
from werkzeug.debug.repr import dump

from superset.security import SupersetSecurityManager
from flask_appbuilder.security.views import expose
from flask_appbuilder.security.manager import BaseSecurityManager
from flask_login import login_user, logout_user
import logging

logger = logging.getLogger(__name__)


class CustomAuthDBView(AuthDBView):
    login_template = 'appbuilder/general/security/login_db.html'

    def __init__(self):
        super().__init__()
        self.authorize_url = "https://new-users.fmh.de/api/public/sessions/authorize/"
        self.info_url = "https://new-users.fmh.de/api/public/"

    def users_api_call(self, token, ip, page):
        """
        basic api-call towards Kastners Users-Authorize-Api, returns the response-object from the http-request
        :param token: (string) the token from the current request to check
        :param ip:  (string) client-ip (user-side) for logging purposes
        :param page: (string) page-id/route for logging purposes
        :return: response-object
        """
        data = {
            "token": token,
            "ip": ip,
            "role": "finance",
            "page": page,
        }
        ret = requests.put(self.authorize_url, data)
        return ret

    def check_user_session(self, token="", ip="127.0.0.1", page="superset"):
        """
        Asks the Users-Api if the given session-token is valid
        :param token: (string) the token from the current request to check
        :param ip:  (string) client-ip (user-side) for logging purposes
        :param page: (string) page-id/route for logging purposes
        :return: (bool) True if the session is valid otherwise False
        """
        response = self.users_api_call(token, ip, page)
        logging.info(vars(response))
        if response:
            status = response.status_code
            logging.info(response.json())
            if status == 200:
                return True
            elif status == 403:
                return False
            else:
                return False

        return False

    def get_user_info(self, token):
        try:
            ret = requests.get("{}/users/by-token/{}".format(self.info_url, token))
            ret = ret.json()
            if "error" in ret:
                return False
            return ret
        except Exception as e:
            return False

    @expose('/login/', methods=['GET', 'POST'])
    def login(self):
        token = request.args.get('token')
        logger.info("token {}".format(token))

        # do the form login
        form = LoginForm_db()
        if form.validate_on_submit():
            user = self.appbuilder.sm.auth_user_db(
                form.username.data, form.password.data
            )
            if not user:
                flash(as_unicode(self.invalid_login_message), "warning")
                return redirect(self.appbuilder.get_url_for_login)
            login_user(user, remember=False)
            return redirect(self.appbuilder.get_url_for_index)

        # or the token login
        if not token:
            token = request.cookies.get('access_token')
        if token is not None:
            if self.check_user_session(token):
                logger.info("session ok")
                new_user = self.get_user_info(token)
                logging.info(new_user)
                user_name = new_user['_id']
                user = self.appbuilder.sm.find_user(username=user_name)
                if not user:
                    role = self.appbuilder.sm.find_role('Public')
                    user = self.appbuilder.sm.add_user(user_name, user_name,
                                                       'new-users',
                                                       new_user['email'],
                                                       role,
                                                       password=uuid.uuid4())
                    logger.info("not user")
                if user:
                    logger.info("user")
                    login_user(user, remember=False)
                    redirect_url = request.args.get('next')
                    if not redirect_url:
                        redirect_url = self.appbuilder.get_url_for_index
                    return redirect(redirect_url)
        else:
            return self.render_template(
                self.login_template, title=self.title, form=form,
                appbuilder=self.appbuilder
            )


class CustomSecurityManager(SupersetSecurityManager):
    authdbview = CustomAuthDBView

    def __init__(self, appbuilder):
        super(CustomSecurityManager, self).__init__(appbuilder)
