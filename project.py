from flask import (Flask,
                   render_template,
                   url_for,
                   request,
                   redirect,
                   flash,
                   jsonify)
from functools import wraps
from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem, User
import datetime
from flask import session as login_session
import random, string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('/var/www/catalog/client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Restaurant Menu Application"

#engine = create_engine('sqlite:///restaurantmenuwithusers.db')
#engine = create_engine('postgresql://catalog:sillypassword@localhost/catalog')
engine = create_engine('postgresql://catalog:password@localhost/catalog')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

#login_reuqired function to not repeat my code every time i want to check if user in or out
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in login_session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

#Display All Restaurants
@app.route('/')
@app.route('/restaurants/')
def restaurants():
    restaurants = session.query(Restaurant).order_by(asc(Restaurant.name))
    items = session.query(MenuItem).order_by(desc(MenuItem.date)).limit(7)
    if 'username' not in login_session:
        return render_template('publicrestaurants.html', restaurants = restaurants, items = items)
    else:
        return render_template('restaurants.html', restaurants=restaurants, items = items)

#ADD New Restaurants
@app.route('/restaurants/new/', methods=['GET', 'POST'])
@login_required
def newRestaurant():
    if request.method == 'POST':
        restaurant = Restaurant(name = request.form['name'])
        restaurant.user_id = login_session['user_id']
        session.add(restaurant)
        session.commit()
        flash("New Restaurant Added")
        return redirect(url_for('restaurants'))
    else:
        return render_template('newrestaurant.html')

#Edit Specifi Restaurant
@app.route('/restaurants/<int:restaurant_id>/edit/', methods=['GET', 'POST'])
@login_required
def editRestaurant(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    if restaurant.user_id != login_session['user_id']:
        alert = "<script>function myFunction()"
        alert += "{alert('You are not authorized to EDIT this restaurant."
        alert += "Please create your own restaurant in order to EDIT.');}</script>"
        alert += "<body onload='myFunction()'>"
        return alert
    previous_name = restaurant.name
    if request.method == 'POST':
        restaurant.name = request.form['name']
        session.add(restaurant)
        session.commit()
        flash("Restaurant %s Edited To %s!"%(previous_name, restaurant.name))
        return redirect(url_for('restaurants'))
    else:
        return render_template('editrestaurant.html', restaurant = restaurant)

# Delete Specifi Restaurant
@app.route('/restaurants/<int:restaurant_id>/delete/', methods=['GET', 'POST'])
@login_required
def deleteRestaurant(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    if restaurant.user_id != login_session['user_id']:
        alert = "<script>function myFunction()"
        alert += "{alert('You are not authorized to DELETE this restaurant."
        alert += "Please create your own restaurant in order to DELETE.');}</script>"
        alert += "<body onload='myFunction()'>"
        return alert
    if request.method == 'POST':
        session.delete(restaurant)
        session.commit()
        flash("Restaurant %s Deleted" % (restaurant.name))
        return redirect(url_for('restaurants'))
    else:
        return render_template('deleterestaurant.html', restaurant=restaurant)


#Display Menu Of Specific Restaurant By Using Restaurant ID
@app.route('/restaurants/<int:restaurant_id>/')
@app.route('/restaurants/<int:restaurant_id>/menu/')
def restaurantMenu(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).first()
    items = session.query(MenuItem).filter_by(restaurant_id=restaurant_id).all()
    creator = getUserInfo(restaurant.user_id)
    if 'username' not in login_session or creator.id != login_session['user_id']:
        return render_template('publicmenu.html', restaurant = restaurant, items = items, creator = creator)
    else:
        return render_template('menu.html', restaurant=restaurant, items=items, creator = creator)

@app.route('/restaurants/<int:restaurant_id>/<string:item_name>/')
def pieceofitem(restaurant_id, item_name):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).first()
    item = session.query(MenuItem).filter_by(name = item_name).first()
    creator = getUserInfo(restaurant.user_id)
    if 'username' not in login_session or creator.id != login_session['user_id']:
        return render_template('pieceofitempublic.html', restaurant = restaurant, item = item, creator = creator)
    else:
        return render_template('pieceofitem.html',
                               restaurant=restaurant,
                               item=item,
                               creator = creator)


# Add New Restaurant Menu
@app.route('/restaurants/<int:restaurant_id>/menu/new/', methods=['GET', 'POST'])
@login_required
def newMenuItem(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    if request.method == 'POST':
        newItem = MenuItem(name = request.form['name'],
                           description = request.form['description'],
                           price = request.form['price'],
                           course = request.form['course'],
                           restaurant_id = restaurant_id,
                           user_id = restaurant.user_id,
                           date=datetime.datetime.now())

        session.add(newItem)
        session.commit()
        flash("new menu item created")
        return redirect(url_for('restaurantMenu', restaurant_id=restaurant_id))
    else:
        return render_template('newmenuitem.html', restaurant_id=restaurant_id)

# Edit Restaurant Menu
@app.route('/restaurants/<string:item_name>/edit/', methods=['GET', 'POST'])
@login_required
def editMenuItem(item_name):
    editedItem = session.query(MenuItem).filter_by(name=item_name).one()
    if editedItem.user_id != login_session['user_id']:
        alert = "<script>function myFunction()"
        alert += "{alert('You are not authorized to EDIT this restaurant."
        alert += "Please create your own restaurant in order to EDIT.');}</script>"
        alert += "<body onload='myFunction()'>"
        return alert
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
            editedItem.description = request.form['description']
            editedItem.price = request.form['price']
            editedItem.course = request.form['course']
        session.add(editedItem)
        session.commit()
        flash("Item Edited Done!")
        return redirect(url_for('pieceofitem',
                                restaurant_id = editedItem.restaurant_id,
                                item_name = editedItem.name))
    else:
        return render_template('editmenuitem.html', editedItem = editedItem)


#Delete Restaurant Menu
@app.route('/restaurants/<string:item_name>/delete/', methods=['GET', 'POST'])
@login_required
def deleteMenuItem(item_name):
    deletedItem = session.query(MenuItem).filter_by(name=item_name).one()
    if deletedItem.user_id != login_session['user_id']:
        alert = "<script>function myFunction()"
        alert += "{alert('You are not authorized to DELETE this restaurant."
        alert += "Please create your own restaurant in order to DELETE.');}</script>"
        alert += "<body onload='myFunction()'>"
        return alert
    if request.method == 'POST':
        session.delete(deletedItem)
        session.commit()
        flash("Item Deleted Done!")
        return redirect(url_for('restaurantMenu', restaurant_id=deletedItem.restaurant_id))
    else:
        return render_template('deletemenuitem.html', deletedItem = deletedItem)

#JSON Section

@app.route('/JSON')
@app.route('/restaurants/JSON')
def RestaurantsJSON():
    restaurants = session.query(Restaurant).all()
    return jsonify(Restaurants=[restaurant.serialize for restaurant in restaurants])

@app.route('/restaurants/<int:restaurant_id>/JSON')
def JSON4OneRestaurant(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    return jsonify(restaurant=[restaurant.serialize])

@app.route('/restaurants/<int:restaurant_id>/menu/JSON')
def MenusJSON(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    items = session.query(MenuItem).filter_by(restaurant_id=restaurant.id)
    return jsonify(MenuItems=[i.serialize for i in items])

@app.route('/restaurants/<int:restaurant_id>/menu/<int:menu_id>/JSON')
def JSON4one(restaurant_id, menu_id):
    item = session.query(MenuItem).filter_by(id=menu_id).one()
    return jsonify(MenuItem=[item.serialize])

@app.route('/catalog.json/')
def CatalogJSON():
    restaurants = session.query(Restaurant).all()
    ind_restautant = [restaurant.serialize for restaurant in restaurants]
    for num in range(len(ind_restautant)):
        items = [item.serialize for item in session.query(MenuItem).filter_by\
            (restaurant_id = ind_restautant[num]['id'])\
            .all()]
        if items:
            ind_restautant[num]['item'] = items
    return jsonify(Catagory=ind_restautant)

#END of JSON Section

# LOGIN
# Create anti-forgery state token

@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('/var/www/catalog/client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
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
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    #Verify User-Email found in database or not.
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
    print "done!"
    return output

    # DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session['access_token']
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return redirect(url_for('restaurants'))
    else:

        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


#Create User
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

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
