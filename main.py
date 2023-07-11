from flask_login import  logout_user, current_user, login_user, login_manager, LoginManager, AnonymousUserMixin
from flask import Flask, render_template, request, url_for, redirect, logging, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import pymysql
#from dB import DB

#pymysql.install_as_MySQLdb()


app = Flask(__name__)

login_manager = LoginManager(app)


# SQLITE Database



app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///circaAdmin.db' #creating the circa admin database


#app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['SECRET_KEY'] = "secret_key"

db = SQLAlchemy(app)  # initialiseing the database
app.app_context().push()


#Creating the model for the database
class orchard_admin(db.Model):
    OR_ID = db.Column(db.Integer, primary_key=True, autoincrement=True) #creating a new column
    OR_Name = db.Column(db.String(100), nullable=False, unique=True) #data type and specifics within ()
    OR_Owner = db.Column(db.String(50), nullable=False )
    OR_Location = db.Column(db.String(150), nullable=False)
    OR_AdminUN = db.Column(db.String(50), nullable=False, unique=True )
    OR_AdminPW = db.Column(db.String(50), nullable=False)
    OR_ADPhone = db.Column(db.String(13), nullable=False)
    OR_ADName = db.Column(db.String(50), nullable=False )

    #creating a string
    def __repr__(self):
        return '<Name %r>' % self.name
    
db.create_all()
 
'''
class User(db.Model, UserMixin):  # creating model
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), nullable=False, unique=True)
    f_name = db.Column(db.String(200), nullable=False)
    l_name = db.Column(db.String(200), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    contacts = db.relationship('Contact', backref='user')  # foreign key relationship initialized

    def __repr__(self):  # creating a string
        return '<name %r>' % self.id



class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200))
    phone = db.Column(db.BigInteger)
    notes = db.Column(db.String(300))
    category = db.Column(db.Text)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # foreign key of user.id made

    def __repr__(self):  # creating a string
        return '<name %r>' % self.id


'''


@login_manager.user_loader
def load_user(OR_ID):
    return orchard_admin.query.get(int(OR_ID))

class Anonymous(AnonymousUserMixin):
  def __init__(self):
    self.username = 'Guest'


@app.route('/')
def mainP():
    
    return render_template('firstP.html')  # Display a basic home page that users can either go to info or log in


@app.route('/moreInfo')
def moreInfo():
    
    return render_template('infoP.html')  # Display a page with basic information regarding Circa 



@app.route('/login', methods=["POST", "GET"])
def login():
    error = None

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")      

        if username == "Admin" and password == "Admin":
             
         orchards = orchard_admin.query.order_by(orchard_admin.OR_Name).all()
         return render_template('CircaAdminHome.html', orchard = orchards)
             
        

        if username == orchard_admin.query.filter_by(OR_AdminUN=username).first():
             user = orchard_admin.query.filter_by(OR_AdminUN=username).first()

             if not user or not check_password_hash(user.password, password):
                 flash('Please check your login details and try again.')    
                 return render_template('login.html')
             login_user(user, remember=True) 
        else:
            
            return render_template('CircaAdminHome.html')

        
            
    return render_template('login.html')

@app.route('/add_orchard', methods=["POST", "GET"])
def add_orchard():
    if request.method == "POST":
            ID =  "001"
            Name = request.form.get("ORname")
            Owner = request.form.get("owner")
            Location = request.form.get("location")
            AdminUN = request.form.get("admUN")
            AdminPW = request.form.get("admPw")
            ADPhone = request.form.get("admPhone")
            ADName = request.form.get("admName")
            new_orchard = orchard_admin(OR_ID=ID, OR_Name=Name, OR_Owner=Owner, OR_Location=Location, OR_AdminUN=AdminUN, OR_AdminPW=AdminPW, OR_ADPhone=ADPhone, OR_ADName=ADName)
            db.session.add(new_orchard)
            db.session.commit()
            flash('New orchard added')
            return render_template('CircaAdminHome.html')
    else:
          orchards = orchard_admin.query.order_by(orchard_admin.OR_Name)
          return render_template('addOR.html', orchard=orchards)
   
   
@app.route("/delete/<int:id>")
def delete(id):
    orchard_to_delete = orchard_admin.query.get_or_404(id)  # the id of Contact is used to identify which to delete
    db.session.delete(orchard_to_delete)  # information of user id to delete sent
    db.session.commit()

    orchards = orchard_admin.query.order_by(orchard_admin.OR_Name).all()
    return render_template('CircaAdminHome.html', orchard = orchards)


@app.route("/update", methods=["POST", "GET"])
def update(id):
    orchard_to_update = orchard_admin.query.get_or_404(id)  # the id of Contact is used to identify which to update
    if request.method == 'POST':
        orchard_to_update.Name = request.form("ORname")
        orchard_to_update.Owner = request.form("owner")
        orchard_to_update.Location = request.form("location")
        orchard_to_update.AdminUN = request.form("admUN")
        orchard_to_update.AdminPW = request.form("admPw")
        orchard_to_update.ADPhone = request.form("admPhone")
        orchard_to_update.ADName = request.form("admName")
        db.session.commit()

        orchards = orchard_admin.query.order_by(orchard_admin.OR_Name).all()
        return render_template('CircaAdminHome.html', orchard = orchards)
    else:
        return render_template('updateOR.html', orchard_to_update = orchard_to_update)
    

@app.route('/logout')
def logout():
    logout_user()  # logs out the current user and sends them to login
    return redirect(url_for('mainP'))


'''

@app.route('/signup', methods=["POST", "GET"])
def registerForm():
    if request.method == "POST":
        user_email = request.form.get("email")
        user_f_name = request.form.get("first_name")
        user_l_name = request.form.get("last_name")
        user_password = request.form.get("password")
        hash_pw = generate_password_hash(user_password, method='sha256')  # hash the password for protection
        new_user = User(email=user_email, f_name=user_f_name, l_name=user_l_name, password=hash_pw)  # creating new user
        db.session.add(new_user)
        db.session.commit()
        return redirect('/signup')

    else:
        users = User.query.order_by(User.date_added)
        return render_template('signup.html', user=users)


@app.route('/adduser', methods=["POST", "GET"])
@login_required
def adduser():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        telephone = request.form.get("telephone")
        note = request.form.get("note")
        category = request.form.get("category")
        user_id = current_user.id  # the current user's id is set to be committed to Contact table
        new_contact = Contact(name=name, email=email, phone=telephone, notes=note, category=category, user_id=user_id)
        db.session.add(new_contact)
        db.session.commit()
        flash('New contact added')
        return redirect('/adduser')

    else:
        contacts = Contact.query.order_by(Contact.date_added)
        return render_template('adduser.html', contact=contacts)


@app.route('/logout')
def logout():
    logout_user()  # logs out the current user and sends them to login
    return redirect(url_for('login'))


@app.route('/view', methods=["GET"])
@login_required
def view():
    contacts = Contact.query.order_by(Contact.date_added).filter(Contact.user_id == current_user.id).all()
    # filtering through the user_id foreign keys of contacts so only the correct user's contacts are displayed
    return render_template('view.html', contact=contacts)


@app.route("/delete/<int:id>")
def delete(id):
    contact_to_delete = Contact.query.get_or_404(id)  # the id of Contact is used to identify which to delete
    db.session.delete(contact_to_delete)  # information of user id to delete sent
    db.session.commit()
    return redirect('/view')


@app.route("/update/<int:id>", methods=["POST", "GET"]).
def update(id):
    contact_to_update = Contact.query.get_or_404(id)  # the id of Contact is used to identify which to update
    if request.method == 'POST':
        contact_to_update.name = request.form['name']
        contact_to_update.email = request.form['email']
        contact_to_update.phone = request.form['telephone']
        contact_to_update.notes = request.form['note']
        contact_to_update.category = request.form['category']
        db.session.commit()
        return redirect('/view')
    else:
        return render_template('update.html', contact_to_update=contact_to_update)
'''

if __name__ == "__main__":
    app.run(debug=True)
     # app.run(debug=True, port=3306 , threaded=True)