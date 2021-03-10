"""
Copyright (c) 2020 Cisco and/or its affiliates.

This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at

               https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""
from flask import Blueprint, flash, g, redirect, render_template, request, session, url_for, current_app
from werkzeug.exceptions import abort
from src.auth import login_required
from src.db import get_db
from src.automation import startAutomatedTask
import threading
import requests
import time
import os
import schedule

bp = Blueprint('portal', __name__)
BLACKLIST_PATH = 'src/Blacklists'
INTELLIGENCE_URL = 'https://www.talosintelligence.com/documents/ip-blacklist'


@bp.route('/', methods=('GET', 'POST'))
@login_required
def home():
    """
    Home Page back-end functionality
    :return:
    """
    # Page Setup
    error = None
    db = get_db()
    active_Blacklists = os.listdir('src/Blacklists')
    if 'autoUpdateBlacklist' not in session:
        session['autoUpdateBlacklist'] = None
    if 'configuredNetworkRouters' not in session:
        session['configuredNetworkRouters'] = []
        error = 'Warning: No Routers configured, Please add devices on the Configuration page.'

    # Define User Interactions
    if request.method == 'POST':
        if request.form.get('autoUpdateBlacklist'):
            session.pop('autoUpdateBlacklist', None)
            session['autoUpdateBlacklist'] = request.form.get('autoUpdateBlacklist')
            # Start Automated Task HERE --- startAutomatedTask(automated_Blacklist)
            print("Thread Count = {}".format(threading.active_count()))
            flaskAPP = current_app._get_current_object()
            automation_Thread = threading.Thread(target=startAutomatedTask,
                                                 args=(current_app._get_current_object(), session['user_id'], str(session['autoUpdateBlacklist']),), daemon=True)
            automation_Thread.start()

    # Retrieve Page Data Set
    router_List = db.execute(
        'SELECT rl.id, host, sshusername, sshpassword'
        ' FROM routerdb rl JOIN user u ON rl.user_id = u.id'
        ' ORDER BY host DESC'
    ).fetchall()

    if error is not None:
        flash(error)
    return render_template('portal/home.html', active_Blacklists=active_Blacklists, router_List=router_List, session=session)


@bp.route('/blacklist', methods=('GET', 'POST'))
@login_required
def blacklist():
    """
    Blacklist Page back-end functionality
    :return:
    """
    # Page Setup
    error = None
    db = get_db()
    if session['autoUpdateBlacklist'] is None:
        error = "Error: No Blacklist selected for automation"
        return redirect(url_for('portal.home'))

    # Define User Interaction
    if request.method == 'POST':
        print()

    # Retrieve Page Data
    task_List = db.execute(
        'SELECT tl.id, task_time, type, description'
        ' FROM tasklog tl JOIN user u ON tl.user_id = u.id'
        ' ORDER BY task_time DESC'
    ).fetchall()

    selected_Blacklist = open('src/Blacklists/{}'.format(session['autoUpdateBlacklist']), "r")
    blacklist_Data = selected_Blacklist.readlines()
    selected_Blacklist.close()

    if error is not None:
        flash(error)
    return render_template('portal/blacklist.html', session=session, task_List=task_List, blacklist_Data=blacklist_Data)


@bp.route('/configure', methods=('GET', 'POST'))
@login_required
def configure():
    """
    Settings Page back-end functionality
    :return:
    """
    # Page Setup
    error = None
    db = get_db()

    if request.method == 'POST':
        if request.form.get('addNewRouter'):
            if db.execute(
                'SELECT id FROM routerdb WHERE host = ?', (request.form['routerHost'],)
            ).fetchone() is None:
                db.execute(
                    'INSERT INTO routerdb (user_id, host, sshusername, sshpassword) VALUES (?, ?, ?, ?)',
                    (session['user_id'], request.form['routerHost'], request.form['routerUser'], request.form['routerPass'])
                )
                db.commit()
            else:
                error = 'User {} is already registered.'.format(request.form['routerHost'])

        if request.form.get('removeRouter'):
            router_Host = str(request.form.get('removeRouter'))
            if db.execute('SELECT id FROM routerdb WHERE host = ?', (router_Host,)).fetchone() is not None:
                db.execute(
                    'DELETE FROM routerdb WHERE host = ?', (router_Host,)
                )
                db.commit()
            else:
                error = 'Router {} does not exist.'.format(router_Host,)

    # Retrieve Page Data Set
    router_List = db.execute(
        'SELECT rl.id, host, sshusername, sshpassword'
        ' FROM routerdb rl JOIN user u ON rl.user_id = u.id'
        ' ORDER BY host DESC'
    ).fetchall()

    if error is not None:
        flash(error)
    return render_template('portal/configure.html', session=session, router_List=router_List)
