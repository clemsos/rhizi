#!/usr/bin/python2.7

#    This file is part of rhizi, a collaborative knowledge graph editor.
#    Copyright (C) 2014-2015  Rhizi
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as published
#    by the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
from functools import wraps

from flask import Flask, render_template, session, request, redirect

from . import rz_api
from . import rz_api_rest
from . import rz_blob
from . import rz_server_ctrl
from . import rz_user
from . import rz_feedback

import logging

from .rz_api_common import sanitize_input__rzdoc_name
from .rz_req_handling import common_resp_handle__client_error

log = logging.getLogger('rhizi')

def init_webapp(cfg, kernel):
    """
    Initialize webapp:
       - call init_rest_interface()
    """

    global webapp

    root_path = cfg.root_path
    assert os.path.exists(root_path), "root path doesn't exist: %s" % root_path

    #
    # init webapp
    #

    # due to magic in os.path.join: os.path.join('/a', '/b') -> '/b',
    # we pass a non-absolute template_d path, even though it is configured as such
    template_d_relpath = cfg.template_d_path
    if template_d_relpath.startswith('/'): template_d_relpath = template_d_relpath[1:]

    webapp = Flask(__name__,
                      static_folder='static',
                      static_url_path=cfg.static_url_path,
                      template_folder=template_d_relpath)

    webapp.config.from_object(cfg)
    webapp.root_path = root_path  # for some reason calling config.from_xxx() does not have effect
    webapp.rz_config = cfg
    webapp.kernel = kernel 

    def login_required(f):
        """
        Security boundary: assert logged-in user before executing REST api call
        """
        @wraps(f)
        def wrapped_function(*args, **kw):
            if session.get('username') is None:
                return redirect('/login')
            return f(*args, **kw)
        return wrapped_function

    # Proxy Mode
    # if cfg.reverse_proxy_host is not None:  
    #     webapp.req_probe__sock_addr = FlaskExt.Req_Probe__sock_addr__proxy(cfg.reverse_proxy_host,
    #                                                                        cfg.reverse_proxy_port)
    # else:
    #     webapp.req_probe__sock_addr = FlaskExt.Req_Probe__sock_addr__direct(cfg.listen_port)
    # # init_rest_interface(cfg, webapp)

    # ERRORS
    @webapp.errorhandler(404)
    def page_not_found(e):
        return "Page not found, sorry"

    # REST API endpoints
    @webapp.route("/api/")
    def flask_route_test():
        return "Welcome to Rhizi API !"

    # users
    webapp.add_url_rule('/index', "index", rz_api.rz_mainpage, methods=['GET'])
    webapp.add_url_rule('/login', "login", rz_user.rest__login, methods=['GET', 'POST'])
    webapp.add_url_rule('/logout', "logout", rz_user.rest__logout, methods=['GET', 'POST'])
    webapp.add_url_rule('/pw-reset', "password-reset", rz_user.rest__pw_reset, methods=['GET', 'POST'])

    webapp.add_url_rule('/feedback', "feedback", rz_feedback.rest__send_user_feedback__email, methods=["POST"])
    webapp.add_url_rule('/match/node-set', "match-node-set", rz_api_rest.match_node_set_by_attr_filter_map, methods=["POST"])

    if cfg.signup_enabled:
        webapp.add_url_rule('/signup', "signup", rz_user.rest__user_signup, methods =['GET', 'POST'] )

    # pretty URLs
    webapp.add_url_rule('/rz/<path:rzdoc_name>', "rz-get-doc", login_required(rz_api_rest.rzdoc__via_rz_url), methods=['GET'])

    # rz-doc CRUD endpoints
    webapp.add_url_rule('/api/rzdoc/clone', "rzdoc_clone", rz_api_rest.rzdoc_clone, methods=["POST"])
    webapp.add_url_rule('/api/rzdoc/search', "rzdoc_search", rz_api_rest.rzdoc__search, methods=["POST"])
    webapp.add_url_rule('/api/rzdoc/<path:rzdoc_name>/create', "rzdoc_create", rz_api_rest.rzdoc__create, methods=["POST"])
    webapp.add_url_rule('/api/rzdoc/<path:rzdoc_name>/delete', "rzdoc_delete", rz_api_rest.rzdoc__delete, methods=['GET', 'DELETE'])  # TODO: rm 'GET' once we have UI deletion support - see #436

    # diff 
    webapp.add_url_rule('/api/rzdoc/diff-commit__set', "rzdoc-diff_commit__set", rz_api_rest.diff_commit__set, methods=["POST"])
    webapp.add_url_rule('/api/rzdoc/diff-commit__topo', "rzdoc-diff_commit__topo", rz_api_rest.diff_commit__topo, methods=["POST"])
    webapp.add_url_rule('/api/rzdoc/diff-commit__attr', "rzdoc-diff_commit__attr", rz_api_rest.diff_commit__attr, methods=["POST"])
    webapp.add_url_rule('/api/rzdoc/diff-commit__vis', "rzdoc-diff_commit__vis", rz_api_rest.diff_commit__vis, methods=["POST"])

    # fetch
    webapp.add_url_rule('/api/rzdoc/fetch/node-set-by-id', "rzdoc-fetch_node-set-by-id", rz_api_rest.load_node_set_by_id_attr, methods=["POST"])
    webapp.add_url_rule('/api/rzdoc/fetch/link-set/by_link_ptr_set', "rzdoc-link-set", rz_api_rest.load_link_set_by_link_ptr_set, methods=["POST"])

    # upload endpoints - this might change to external later, keep minimal and separate
    webapp.add_url_rule('/blob/upload', "blob-upload",  rz_blob.upload, methods=['POST'])

    # [!] this is for development only. served from frontend web server in production
    webapp.add_url_rule('/blob/uploads/<path:path>', "blob-uploads", rz_blob.retreive, methods=['GET', 'DELETE'])

    # server administration: access restricted to localhost
    webapp.add_url_rule('/monitor/server-info', "monitor-server-info", rz_server_ctrl.monitor__server_info, methods=['GET'])
    webapp.add_url_rule('/monitor/user/list', "monitor-user-list", rz_server_ctrl.rest__list_users, methods=['GET'])

    # redirects
    def index(): return redirect('/index')
    webapp.add_url_rule('/', '/index', index, methods=['GET'])
    webapp.add_url_rule('/index.html', index, methods=['GET'])

    return webapp

