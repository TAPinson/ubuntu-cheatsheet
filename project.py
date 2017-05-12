from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from flask import session as login_session
from flask import make_response
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from database_setup import Base, Application, Category, User
import random
import string
import httplib2
import json
import requests


app = Flask(__name__)

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']

APPLICATION_NAME = "Ubuntu Cheat Sheet"
base = "ubuntuapps.html"

#Connect a database and create database session
engine = create_engine('sqlite:///ubuntuapps.db')
Base.metadata.bind = engine
DBSession = sessionmaker (bind=engine)
session = DBSession()

# User Helper Functions ######################################################################


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

# Connect to Ubuntu Apps ######################################################################


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    base = "ubuntuapps.html"
    return render_template('login.html', base=base, STATE=state)


# Connect with facebook account
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
        session.rollback()
        if request.args.get('state') != login_session['state']:
            response = make_response(json.dumps('Invalid state parameter.'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response
        access_token = request.data
        print "access token received %s " % access_token

        app_id = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_id']
        app_secret = json.loads(
            open('fb_client_secrets.json', 'r').read())['web']['app_secret']
        url = ('https://graph.facebook.com/v2.8/oauth/access_token?'
               'grant_type=fb_exchange_token&client_id=%s&client_secret=%s'
               '&fb_exchange_token=%s') % (app_id, app_secret, access_token)
        h = httplib2.Http()
        result = h.request(url, 'GET')[1]
        data = json.loads(result)
        # Extract the access token from response
        token = 'access_token=' + data['access_token']
        # Use token to get user info from API
        url = 'https://graph.facebook.com/v2.8/me?%s&fields=name,id,email' % token
        # strip expire tag from access token
        #token = result.split("&")[0]
        http = httplib2.Http()
        result = http.request(url, 'GET')[1]
        # print "url sent for API access:%s"% url
        # print "API JSON result: %s" % result
        data = json.loads(result)
        login_session['provider'] = 'facebook'
        login_session['username'] = data["name"]
        login_session['email'] = data["email"]
        login_session['facebook_id'] = data["id"]
        # The token must be stored in the login_session in order to properly logout, let's strip out the information before the equals sign in our token
        stored_token = token.split("=")[1]
        login_session['access_token'] = stored_token
        # Get user picture
        url = 'https://graph.facebook.com/v2.4/me/picture?%s&redirect=0&height=200&width=200' % token
        h = httplib2.Http()
        result = h.request(url, 'GET')[1]
        data = json.loads(result)
        login_session['picture'] = data["data"]["url"]
        # see if user exists
        user_id = getUserID(login_session['email'])
        if not user_id:
            user_id = createUser(login_session)
        login_session['user_id'] = user_id
        output = ''
        output += '<h1>Welcome, '
        output += login_session['username']
        output += '!</h1>'
        output += '<img src="'
        output += login_session['picture']
        output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
        flash("Now logged in as %s" % login_session['username'])
        return output


# Connect with google account
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    print 'CHECK 1'
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code, now compatible with Python3
    code = request.data
    print 'CHECK 2'
    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
        print credentials, 'THE CREDENTIALS SHOULD BE TO THE LEFT OF THIS'
    except FlowExchangeError:
        print 'CHECK 3'
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print 'CHECK 4'
    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    # Submit request, parse response - Python3 compatible
    h = httplib2.Http()
    response = h.request(url, 'GET')[1]
    str_response = response.decode('utf-8')
    result = json.loads(str_response)
    print 'CHECK 5'
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print 'CHECK 6'
    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Store the access token in the session for later use.
    login_session['access_token'] = access_token
    login_session['gplus_id'] = gplus_id
    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    print 'CHECK 7'
    data = answer.json()
    login_session['provider'] = 'google'
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # see if user exists, if it doesn't make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    return output

# Disconnect based on provider - Revoke a current user's token and reset their login_session #####


@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            print login_session['gplus_id']
            del login_session['gplus_id']
            # print login_session['credentials']
            # del login_session['credentials']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
            del login_session['username']
            del login_session['email']
            del login_session['picture']
            del login_session['user_id']
            del login_session['provider']
            flash("You have successfully been logged out.")
            return redirect(url_for('showHome'))
        else:
            flash("You were not logged in")
            return redirect(url_for('showHome'))

# Disconnect if using google ##################################################################
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] != '200':
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response

# Disconnect if using facebook ###############################################################
@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"

# Render the homepage #######################################################################


@app.route('/')
@app.route('/ubuntuapp/')
def showHome():
    # categories = session.query(Category).order_by(asc(Category.name))
    return render_template(base)

############################################################################################


@app.route('/ubuntuapp/apps')
def showApps():
    html_file = 'apps.html'
    print 'check 1'
    apps = session.query(Application).all()
    return render_template(html_file, apps=apps, app=app, base=base)

#Handler for creating a new app ###########################################################


@app.route('/ubuntuapp/apps/newapp', methods=['GET', 'POST'])
def newApp():
    if request.method == 'POST':
        newApp = Application(
            name=request.form['name'],
            description=request.form['description'],
            repository=request.form['repository'],
            aptget=request.form['aptget'],
            category=request.form['category'],
            user_id = login_session['user_id']
            )
        session.add(newApp)
        flash('New Application %s Successfully Created' % newApp.name)
        session.commit()
        return redirect(url_for('showApps'))
    html_file = 'newapp.html'
    return render_template(html_file, base=base)

# Handler for deleting an app ##############################################################

@app.route('/ubuntuapp/apps/<int:id>/delete', methods=['GET', 'POST'])
def deleteApp(id):
    if request.method == 'POST':
        print 'you pressed the confirm button'
        apps = session.query(Application).filter_by(id=id)
        for app in apps:
            print 'heres the for app in apps'
            session.delete(app)
            session.commit()
            print 'app deleted!'
            return redirect('/ubuntuapp/apps')

    html = 'deleteapp.html'
    apps = session.query(Application).filter_by(id=id)
    for app in apps:
        print app.id
        print app.name
        return render_template(html, base=base, app=app)


# Handler for editing an app ##############################################################

@app.route('/ubuntuapp/apps/<int:id>/edit', methods=['GET', 'POST'])
def editApp(id):
    if request.method == 'POST':
        print 'you pressed the confirm button'
        apps = session.query(Application).filter_by(id=id)
        for app in apps:
            print 'heres the for app in apps'
            app.name = app.name
            if request.form['description']:
                app.description = request.form['description']
            elif request.form['command']:
                app.aptget = request.form['command']
            elif request.form['repository']:
                app.repository = request.form['repository']
            elif request.form['category']:
                app.category=request.form['category']

            return redirect('/ubuntuapp/apps')
    html = 'editapp.html'
    apps = session.query(Application).filter_by(id=id)
    for app in apps:

        print app.id
        print app.name
        return render_template(html, base=base, app=app)

############################################################################################


@app.route('/ubuntuapps/apps/myapps')
def myApps():
    html_file = 'myapps.html'
    return render_template(html_file, base=base)


@app.route('/categories')
def showCategories():
    html_file = 'categories.html'
    return render_template(html_file, base=base)


# Handlers for viewing apps by category ################################################################################


@app.route('/apps/media')
def showMedia():
    html_file = 'media.html'
    print 'check 1'
    apps = session.query(Application).filter_by(category = 'media').all()
    return render_template(html_file, apps=apps, base=base)

@app.route ('/apps/development')
def showDevelopment():
    html_file = 'media.html'
    apps = session.query(Application).filter_by(category='development').all()
    return render_template(html_file, apps=apps, base=base)

@app.route('/apps/tools')
def showTools():
    html_file = 'media.html'
    apps = session.query(Application).filter_by(category='tools').all()
    return render_template(html_file, apps=apps, base=base)


@app.route('/apps/fixes')
def showFixes():
    html_file = 'media.html'
    apps = session.query(Application).filter_by(category='fixes').all()
    return render_template(html_file, apps=apps, base=base)


# JSON APIs to view Restaurant Information ###########################################################################


@app.route('/ubuntuapp/<int:id>/apps/JSON')
def showAppJSON(id):
    catalog = session.query(Application).filter_by(id=id).all()
    return jsonify(ItemCatalog=[i.serialize for i in catalog])

####################################################################################################


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)

