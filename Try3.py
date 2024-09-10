from flask import Flask, render_template, redirect, url_for, request, jsonify, flash
#from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash

from ast import literal_eval
import ast
import os
from email.mime.text import MIMEText
from flask import  json, render_template, redirect, url_for, flash

from flask_migrate import Migrate

from Forms import RegistrationForm,LoginForm,ResetPasswordForm,RequestResetForm

from mail import send_registration_email


from flask_login import LoginManager, login_user, logout_user, current_user
from read_User_credentials import read_credentials
from DbModel import ButtonSettings ,User , db,app
global usernameU, password, MailUsername, MailPassword
usernameU, password, MailUsername, MailPassword ,SECRET_KEY,default_secret_key= read_credentials()
from flask import  session as sessions
# Global variable to store form data
form_data = {}
gsession={}
thisdict =	{ }
saved_num_buttons = 0
saved_button_labels = []
saved_button_states = []
result = []

#app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hjhhNewDb.db'
app.config['SESSION_COOKIE_NAME'] = 'your_session_cookie'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

#db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# SMTP_SERVER = 'smtp.gmail.com'
# SMTP_PORT = 587
# SMTP_USERNAME = os.getenv("SMTP_USERNAME")
# SMTP_PASSWORD =  MailPassword
# SENDER_EMAIL = MailUsername 


recipients = "leon_asha@hotmail.com"
bodyh ="vediamo Thank  funziona  you for registering!  out"

migrate = Migrate(app, db)

db.init_app(app)
migrate.init_app(app, db)

# Funzione per caricare un utente
@login_manager.user_loader
def load_user(user_id):
    print(" 51 user_id ",user_id)
    print("52 User.query.get(int(user_id))==", User.query.get(int(user_id)))
    print("60 type(User.query.get(int(user_id))==", type(User.query.get(int(user_id))))
    return User.query.get(int(user_id))  # Assuming user ID is stored as an integer
def create_session(email):
    print(" 45 create_session ")
    #session_id = str(uuid.uuid4())  # Corretto: Usa il valore di session_id
    session_id = "f3497e84-3ccf-48bf-bc3d-19c6255b9459"  # Corretto: Usa il valore di session_id
    sessions[session_id] = email
    sessions["email"] = email
    gsession[session_id] = email
    
    thisdict[session_id] = email
    thisdict["brand"] = "Ford" 
    #sessions[session_id] = email
    print (" 70 di gsession[session_id]  create_session email", gsession[session_id]  ) 
    print ("51 di create_session email",email)   
    print ("53 di sessions['email']====",sessions["email"])
    return session_id
def get_user_by_session(session_id):
    #email = sessions.get(session_id)
    
    
    email = gsession.get(session_id)
    print ("41 session_id",session_id)
    print ("42  email",email)
    
    print(" 85 gsession[session_id]=================")
    print( thisdict[session_id]  )
    
    if email:
        print("  45 User.get(email) =",User.query.filter_by(email=email).first().email)
        return User.query.filter_by(email=email).first()
    return None
def custom_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        print(" ======================= start =custom_login_required ====================================")
        global form_data
        user_agent = request.headers.get('User-Agent', '')
        print(" 87 User-Agent in custom_login_required:", user_agent)
        if current_user.is_authenticated:
            print(" 57  current_user.is_authenticated  ^^^^^^^^^^^^^^^^^^ ",current_user.is_authenticated)
            return f(*args, **kwargs)
            #f(*args, **kwargs)
        if 'ESP32HTTPClient' in user_agent:
            session_id = request.cookies.get('session_id')  # Get session ID from cookies
            print("session_id ==",session_id)
            
            print(" 100 gsession[session_id]")
            print( thisdict[session_id]  )
            print(" 109 gsession[session_id]=================")
            print( thisdict[session_id]  )
            print(thisdict)
            print(" 103 gsession[session_id]----------------")
            user = get_user_by_session(session_id)
            print(" 96 gsession[session_id]   = " ,gsession[session_id] )
            print("76  current_user.is_authenticated",current_user.is_authenticated)
            if gsession[session_id] or current_user.is_authenticated:
                print("81 session_id ==",session_id)
                return f(*args, **kwargs)
            #f(*args, **kwargs)
            else:
                return jsonify({'status': 'error', 'message': 'User not authenticated.'}), 403
        # Initialize `user` variable to None
    return decorated_function

@app.route('/loginPg', methods=['GET', 'POST'])
def login():
    print(" **************************************** start =cloginPg ****************************************")
    global form_data
    if current_user.is_authenticated:
        print("149   current_user.is_authenticated: ",current_user.is_authenticated)
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if request.method == 'POST':
        user_agent = request.headers.get('User-Agent', '')
        print("201 User-Agent in login:", user_agent)
        if 'Kivy' in user_agent:
            # Handle Kivy-specific login if needed
            pass
        elif 'python-requests' in user_agent or 'PostmanRuntime' in user_agent or 'ESP32HTTPClient' in user_agent :
            data = request.get_json()
            if data:
                email = data.get('email')
                password = data.get('password')
                print("203 Email:", email)
                print("Password:", password)               
                user = User.query.filter_by(email=email).first()
                if user and user.check_password(password):
                    login_user(user)  # Ensure this is called
                    session["email"] = email 
                    sessions["email"] = email 
                    print(" 220  current_user.is_authenticated  ^^^^^^^^^^^^^^^^^^ ",current_user.is_authenticated)
                    session_id = create_session(email)
                    return jsonify({'status': 'success', 'message': 'Login successful!', 'session_id': session_id})
                else:
                    return jsonify({'status': 'error', 'message': 'Invalid email or password.'}), 401      
        elif 'Mozilla' in user_agent:
            if form.validate_on_submit():
                print("133")
                # Gestione del form HTML
                email = form.email.data
                password = form.password.data
                print("137  email",email)
                print("138  password ",password)
            user = User.query.filter_by(email=email).first()
            if user and user.check_password(password):
                session_id = create_session(email)
                # Adding or updating the 'session_id' key
                login_user(user)  # Ensure this is called
                session["email"] = email ##################################********************
                print ("170 di sessions['email']====",sessions["email"])
                print ("171 di sessions['email']====",session["email"])
                form_data.update({'session_id': session_id})
                #################################################################
                if request.is_json:
                    return jsonify({'status': 'success', 'message': 'Login successful!'})
                else:
                    return redirect(url_for('dashboard'))
            else:
                error_message = 'Invalid email or password.'
                if request.is_json:
                    return jsonify({'status': 'error', 'message': error_message})
                else:
                    flash(error_message)
            #################################################################
    print(" ************** 207 ********************* END  = /loginPg ****************************************")
    return render_template('DBlogin copy.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():   
    user_agent = request.headers.get('User-Agent', '')
    print("238  User-Agent in custom_login_required:", user_agent)
    # Initialize user variable to None
    # Handle Kivy-specific logic
    if 'python-requests' in user_agent:
        #print(" 243 email = ")
        #print(" password = ",password) 
        #print("245 ")
        data = request.get_json()
        if data is None:
            return jsonify({"error": "Missing JSON payload"}), 400
        #else :
        print(" 250 dat is wok")
        print(" 'username' ", data ['username'])
        print(" 'email' ", data ['email'])
        print(" 'password' ", data ['password'])
        username=data ['username']
        password=data ['password']
        email=data ['email']
        user = User.query.filter_by(email=email).first()
        #print( " 259  username ",user.username)
        print(" 260 ok ricerca")
        if user:
            print( " 259  username ",user.username)
            print(" 261ok ricerca")
            return jsonify({'status': 'Email already registered.'} )
            #return jsonify({'status': 'success', 'message': f'Hello,'})
        new_user = User(email=data ['email'], password=password, username=username)
        db.session.add(new_user)
        db.session.commit()
        body ="Thank  funziona  you for registering!  out from kivy "
        print(f" line 62 email: {email}")
        send_registration_email(body,email)
        print(" done rigtration---")
        #return " done"
        return jsonify({'status': ' Registration success', 'message': f'Hello,'})
                #username = data.get('username')
        #print(" 248  username ",username)
    else :    
        form = RegistrationForm()
        print("126 ")
        if form.validate_on_submit():
            print("155 ")
            username = form.username.data
            email = form.email.data
            password = form.password.data
            print("132 username",username)
            # Check if user already exists
            user = User.query.filter_by(email=email).first()
            if user:
                flash('Email already registered.')
                return redirect(url_for('register'))
            new_user = User(email=email, password=password, username=username)
            db.session.add(new_user)
            db.session.commit()
            
            body ="Thank  funziona  you for registering!  out"
            print(f" line 62 email: {email}")
            send_registration_email(body,email)
            
            flash('dopo in .py file Registration successful! fro mweb ')
            return redirect(url_for('login'))
        print("251 ")
        return render_template('DBregister copy.html', form=form)

@app.route('/protected', methods=['GET'])
@custom_login_required
def protected():
    print("  281 ********************************")
    session_id = request.headers.get('session_id')
    session_idc = request.cookies.get('session_id')
    print("session_id",session_id)
    print("session_idc",session_idc)   
    user_agent = request.headers.get('User-Agent', '')
    print("User-Agent in custom_login_required:", user_agent)
    # Initialize `user` variable to None
    user = None
    # Handle Kivy-specific logic
    if 'Kivy' in user_agent:
        session_idc = request.cookies.get('session_id')    
    # Handle JSON requests (e.g., Postman)
    elif 'python-requests' in user_agent or 'PostmanRuntime' in user_agent:
        print("434 Form Username:")    
    # Handle form submissions from browsers
    elif 'Mozilla' in user_agent:    
        print("Form Username:")
    # Handle other User-Agents
    else:
        #session_id = request.headers.get('session_id')
        session_idc = request.headers.get('Mype')
    email = sessions.get(session_idc)
    return jsonify({'status': 'success', 'message': f'Hello, {email}'})
@app.route('/')
def home():
    return redirect(url_for('login'))
@app.route('/dashboard', methods=['GET', 'POST'])
@custom_login_required
def dashboard():
    print("196")
    if 'email' not in session:
        print("183")
        return redirect(url_for('login'))
    if request.method == 'POST':
        print("186")
        num_buttons = request.form['num_buttons']
        button_labels = [request.form.get(f'button{i+1}') for i in range(int(num_buttons))]
        # Handle saving button settings logic
        print("email",session['email'])
        print("num_buttons",num_buttons)
        print("button_labels",button_labels)
        return render_template('DBdashboard.html', email=session['email'])
    print("243   session['email']",session['email'])
    return render_template('DBdashboard.html', email=session['email'])

aved_button_id = None
aved_button_label = None
saved_button_Pin = []
rin=0   
@app.route('/Pstate', methods=['GET', 'POST'])
@custom_login_required
def Pupdate_state():
    global aved_button_id, aved_button_label, Sbutton_data, button_data
    global saved_num_buttons, saved_button_labels, saved_button_states
    global saved_button_Pin

    user_agent = request.headers.get('User-Agent', '')
    print(" 602 User-Agent in custom_login_required:", user_agent)
    
    if 'ESP32HTTPClient' in user_agent:
        session_idc = request.cookies.get('session_id')
        print("604 session_idc", session_idc)
        myID = get_user_by_session(session_idc)
        settings = ButtonSettings.query.filter_by(user_id=myID.id).first()
        print("607 myID", myID)
        print("608 button_settings", settings)
    else: 
        user = current_user
        settings = user.settings

    print("438 settings.num_buttons", settings.num_buttons if settings else "No settings")
    # Dati di esempio
    buttonPins = [2, 5, 12, 14, 15, 18, 19, 21, 22, 23, 25, 26, 27, 32, 33]
    if settings:
        ###########################
        n = settings.num_buttons
        first_n_elements = buttonPins[:n]
        print("  445 N button_Pin -:",n)
        print("  446  first_n_elements -:",first_n_elements)
        # Stampa il risultato
        print(first_n_elements)
        ############################
        saved_button_Pin = first_n_elements
        #saved_button_Pin = [1] * settings.num_buttons
        print("  441  saved_button_Pin -:",saved_button_Pin)
        saved_button_labels = literal_eval(settings.button_labels)
        saved_button_states = literal_eval(settings.button_states)
        num_buttons = settings.num_buttons
        print(" 445  saved_button_labels = ",saved_button_labels)
        print(" 446  type(saved_button_labels = ",type(saved_button_labels))
        print(" 448 ",saved_button_labels)
    else:
        saved_button_Pin = []
        saved_button_labels = []
        saved_button_states = []
        num_buttons = 0

    Sbutton_data = []

    if request.method == 'POST':
        data = request.get_json()
        #button_id = int(data.get('buttonPin'))
        button_id = data.get('buttonPin')
        
        print(" 461 button_id ",button_id)
        
        button_label = data.get('buttonLabel')
        print(" 457  button_id = ",button_id)
        for rin in range(num_buttons):
            saved_button_Pin[rin] = button_id

        aved_button_id = button_id
        aved_button_label = button_label

        Sbutton_data.append({'buttonId': button_id, 'buttonLabel': button_label})
        sessions['button_id'] = button_id
        sessions['button_label'] = button_label
        print("-line 368 ---Sbutton_data", Sbutton_data)
        print("-line 468 ---sessions.get('button_label')", sessions.get('button_label'))
        print("-line 470 ---sessions['button_label']    ", sessions['button_label'] )
        if 'ESP32HTTPClient' in user_agent:
            return 'ok' 
        #jsonify({'buttonLabel': button_label , 'state': saved_button_states})
        else:
            return render_template('hity.html', button_data=Sbutton_data)

    # if not Sbutton_data:
    #     button_id = sessions.get('button_id')
    #     button_label = sessions.get('button_label')
    #     Sbutton_data = [{'buttonId': button_id, 'buttonLabel': button_label}]
    #     print('683 Sbutton_data==', Sbutton_data)
    # aved_button_id = aved_button_id if 'aved_button_id' in globals() else 0
    # aved_button_label = aved_button_label if 'aved_button_label' in globals() else 'default'
    # button_id = aved_button_id
    # button_label = aved_button_label
    # button_data = [{'buttonId': button_id, 'buttonLabel': button_label}]
    
    result = []
    resultp = []

    for i in range(len(saved_button_Pin)):
        button_id = saved_button_Pin[i]
        print("499  saved_button_Pin[i] =",saved_button_Pin[i])
        button_label = saved_button_labels[i]
        print('491 button_label:::', button_label)
        resultp.append(button_label)
        result.append({'buttonId': button_id, 'buttonLabel': button_label})

    print('698 result:::', result)
    print('699 resultp --=', resultp)
    
    if 'ESP32HTTPClient' in user_agent:
        return jsonify({'buttonLabel': saved_button_labels, 'state': saved_button_states})

    if request.method == 'GET':
        '''
        print("-line 508  ---sessions['button_label']    ", sessions['button_label'] )
        print("-line 509  ---sessions['button_id']    ", sessions['button_id'] )
        print(" 500  in get ")
        Sbutton_data.append({'buttonId': sessions['button_id'], 'buttonLabel':  sessions['button_label']})
        print(" 512   in get Sbutton_data=  ", Sbutton_data)
        print(" 513  in get type(Sbutton_data)=  ",type(Sbutton_data))
        print(" 514    in get type(result)   ", type(result))
        '''
        ###
        # Verifica se Sbutton_data è una lista con almeno un elemento
        if isinstance(Sbutton_data, list) and len(Sbutton_data) > 0:
            # Estrai il primo dizionario dalla lista
            data_dict = Sbutton_data[0]
            # Verifica che il dizionario contenga le chiavi 'buttonId' e 'buttonLabel'
            if 'buttonId' in data_dict and 'buttonLabel' in data_dict:
                # Estrai le liste di buttonId e buttonLabel
                button_ids = data_dict['buttonId']
                button_labels = data_dict['buttonLabel']
                # Crea la struttura trasformata
                transformed_data = [{'buttonId': button_ids[i], 'buttonLabel': button_labels[i]} for i in range(len(button_ids))]
                # Stampa il risultato
                print('transformed_data =  ',transformed_data)
            else:
                print(" 534 ")
                print("Il dizionario non contiene le chiavi 'buttonId' e 'buttonLabel'.")
        else:
            print(" 538 ")
            print("Sbutton_data non è una lista con almeno un elemento.")
        return render_template('toggle.html', num_buttons=num_buttons, 
                            button_labels=resultp, button_states=saved_button_states,
                            button_data=result)
                            #button_data=transformed_data)
    else:
        return render_template('toggle.html', num_buttons=num_buttons, 
                            button_labels=resultp, button_states=saved_button_states,
                            button_data=Sbutton_data)

@app.route('/state', methods=['GET','POST'])
@custom_login_required
def update_state():
    print("182")    
    global saved_num_buttons, saved_button_labels, saved_button_states
    # Recupera l'utente corrente
    user_agent = request.headers.get('User-Agent', '')
    print(" 307 User-Agent in custom_login_required:", user_agent)
    if 'ESP32HTTPClient' in user_agent:
        session_idc = request.cookies.get('session_id')
        print("311  session_idc",session_idc) 
        myID=get_user_by_session(session_idc)
        button_settings = ButtonSettings.query.filter_by(user_id=myID.id).first()
        print("314   myID",myID)
        print("315  button_settings", button_settings)
        if not button_settings:
            print("423   -----" )
            return jsonify({'error': 'Button settings not found for the current user.'}), 404
        else :
            print("426   myID" )
            return jsonify({'buttonLabel': button_settings.button_labels, 'state':  button_settings.button_states})
    else: 
        user = current_user
        button_settings = ButtonSettings.query.filter_by(user_id=user.id).first()
        
        print("319  settings.num_buttons   ", button_settings.num_buttons)
        # Recupera le impostazioni del pulsante per l'utente corrente

        if not button_settings:
            return jsonify({'error': 'Button settings not found for the current user.'}), 404
        # Ottieni i dati JSON dalla richiesta
        data = request.get_json()
        button_id = int(data.get('buttonId'))
        print("button_id",button_id)
        new_state = data.get('state')
        button_label = data.get('buttonLabel')
        print("button_label",button_label)   
        print("---Line 108 ---------data from esp32 /state-------button_id---------")
        print(button_id)
        print("-@@@@@@@@@@--data from esp32 /state-------button_label---------")
        print(button_label)
        print("button_settings.button_states[button_id] 389 ",button_settings.button_states[button_id])    
        print("-----------fine /state ---data from esp32 ----------------")
        # Aggiorna lo stato del pulsante nel database
        #button_settings.button_states[button_id] = "new_state"
        print("384")
        print(type(new_state))
        print("Updated button_states 386 ", button_settings.button_states)
        print("Updated button_labels:", button_settings.button_labels)
            # Ensure button_states is a list or dictionary
        button_states = literal_eval(button_settings.button_states)
        button_states[button_id] = new_state
        button_settings.button_states = str(button_states)
        db.session.commit()    
        button_settings = ButtonSettings.query.filter_by(user_id=user.id).first()
        # Passa i dati necessari al template Jinja
        num_buttons = len(button_settings.button_labels)  # Numero dei pulsanti
        button_labels = button_settings.button_labels  # Etichette dei pulsanti
        button_states = button_settings.button_states  # Stati dei pulsanti    
        return jsonify({'message': f'State updated for button {button_label}'})
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    form = RequestResetForm()
    if form.validate_on_submit():
        print("155",form.email.data)
        #user = User.query.filter_by(email=email).first()
        user = User.query.filter_by(email=form.email.data).first()
        print("155")
        if user:
            token = user.get_reset_token()
            body = f"To reset your password, visit the following link: {url_for('reset_token', token=token, _external=True)}"
            send_registration_email(body,form.email.data)
            flash('An email has been sent with instructions to reset your password.', 'info')
            print(body)
            return redirect(url_for('login'))  
    return render_template('reset_request.html', form=form)
@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    user = User.verify_reset_token(token)
    if not user:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.password_hash = generate_password_hash(form.password.data)
        db.session.commit()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', form=form)
def string_to_list(s):
    # Convert the string representation of a list to an actual list
    return ast.literal_eval(s)
def custom_list_to_json(lst):
    # Join elements without quotes, assuming they are valid JSON tokens (like variable names)
    json_string = "[" + ", ".join(lst) + "]"
    return json_string

from DbModel import db
from flask import Flask, request, redirect, url_for, flash, session, jsonify, render_template
from DbModel import db, User, ButtonSettings
import json

@app.route('/toggle', methods=['GET', 'POST'])
@custom_login_required
def toggle():
    if 'email' not in session:
        flash('You are not logged in. Please log in to access this page.', 'danger')
        return redirect(url_for('login'))    
    user = User.query.filter_by(email=session['email']).first()   
    print("660 di sessions['email']====", session["email"])
    print("661 user.id", user.id)   
    if request.method == 'POST':        
        user_agent = request.headers.get('User-Agent')
        print("665  user_agent = ", user_agent)
        if 'Kivy' in user_agent or 'python-requests' in user_agent:
            print("475")        
        # if request.is_json:
            # Gestione della richiesta JSON dall'app mobile
            data = request.get_json()
            num_buttons = data.get('num_buttons')
            button_labels = data.get('button_labels')
        else:
            num_buttons = int(request.form['num_buttons'])
            button_labels = [request.form[f'button{i+1}'] for i in range(num_buttons)]            

        button_states = ['off'] * num_buttons
        print("677  num_buttons =", num_buttons)   
        print("678  button_labels =", button_labels)  
        print("679  button_states =", button_states)   

        # Check if there are existing button settings for this user
        existing_button_settings = ButtonSettings.query.filter_by(user_id=user.id).first()
        if existing_button_settings:
            print("Deleting existing button settings for user", user.id)
            db.session.delete(existing_button_settings)
            db.session.commit()

        # Create new button settings
        new_button_settings = ButtonSettings(
            num_buttons=num_buttons,
            button_labels=json.dumps(button_labels),
            button_states=json.dumps(button_states),
            user_id=user.id
        )
        print("679 db.session.add(new_button_settings)")
        db.session.add(new_button_settings)
        db.session.commit()
    # Retrieve the button settings for rendering
    button_settings = ButtonSettings.query.filter_by(user_id=user.id).first()
    print("537 di sessions['email']====", session["email"])
    print("539 button_settings.id ]====", button_settings)
    if button_settings:
        num_buttons = button_settings.num_buttons
        button_labels = button_settings.button_labels
        button_states = button_settings.button_states       
        # Example usage
        print("545 button_settings ====", button_settings)
        print(" 721 di button_labels====", button_labels)
        print(" 722 ==", button_states)
        
        # Convert JSON strings to lists
        my_list = string_to_list(button_labels)
        button_states = string_to_list(button_settings.button_states)
        button_labels= my_list 
        
  
    else:
        print(" my ")
        num_buttons = 0
        button_labels = []
        button_states = []

    if request.is_json:
        print(" 732 ")
        return jsonify({'num_buttons': num_buttons, 'button_labels': button_labels, 'button_states': button_states}), 200
    else:       
        user_agent = request.headers.get('User-Agent')
        if 'Kivy' in user_agent:
            print(" 737 ")
            return jsonify({'num_buttons': num_buttons, 'button_labels': button_labels, 'button_states': button_states})
        else:
            print("web 543 ")
            print("num_buttons 564  num_buttons", num_buttons)
            print("num_buttons 566  button_settings.button_states", button_settings.button_states)
            return render_template('toggle.html', num_buttons=num_buttons, button_labels=button_labels, button_states=button_states)



@app.route('/addwe', methods=['GET','POST'])
@custom_login_required
def add_button_web():
    print("  549  ")
    return render_template('addbuttons.html', email=session['email'])

from DbModel import db
@app.route('/add', methods=['GET','POST'])
@custom_login_required
def add_button():
    print("  556  ")
    user = current_user
    settings = ButtonSettings.query.filter_by(user_id=user.id).first()
    user_agent = request.headers.get('User-Agent')
    if 'Kivy' in user_agent:
        print("*************  567 **************************")
        data = request.get_json()
        new_button_label = data.get('buttonLabel')      
        #settings = ButtonSettings.query.filter_by(user_id=1).first()
        print(" 767 button_settings. ",settings.button_labels)
        button_labels = settings.button_labels
        print(" 540   button_labels PRIMA  ",button_labels)
        button_labels = ast.literal_eval(settings.button_labels)
        print(" 540   button_labels PRIMA  ",button_labels)
        print(" 582 settings.button_labels PRIMA    ", settings.button_labels)       
        print(" 583  TYPE button_labels PRIMA  ", type(button_labels))
        #print(" 583  TYPE button_labels PRIMA  ", type(button_labels))
        print(" 583  Typ(settings.button_labels PRIMA  ", type(settings.button_labels))       
        # Add the new button label and default state
        # button_labels.append("leeron")
        print("422   button_labels  ",button_labels)
        # Update the settings object
        settings.button_labels = str(button_labels)
        #####settings.num_buttons += 1
        db.session.commit()
        print("572 new_button_label   ",new_button_label)
        if not new_button_label:
            flash('No button label provided.', 'danger')
            return jsonify({'error': 'No button label provided.'}), 400
        # Convert string representations of lists to actual lists
        button_labels = ast.literal_eval(settings.button_labels)
        button_states = ast.literal_eval(settings.button_states)
        print(" 540   button_labels PRIMA  ",button_labels)
        print(" 581 button_states PRIMA    ", button_states)
        print(" 582 settings.button_labels PRIMA    ", settings.button_labels)
        print(" 583  TYPE button_labels PRIMA  ", type(button_labels))
        print(" 583  Typ(settings.button_labels PRIMA  ", type(settings.button_labels))
        # Add the new button label and default state
        button_labels.append(new_button_label)
        button_states.append('off')
        print("588   new_button_label  ",new_button_label)
        print(" 592   button_labels  DOPO   ",button_labels)
        print(" 593 button_states DOPO      ", button_states)
        # Update the settings object
        settings.button_labels = str(button_labels)
        settings.button_states = str(button_states)
        settings.num_buttons += 1
        try:
            print(" 560")
            db.session.commit()
        except Exception as e:
            print(f"An error occurred: {e}")
            db.session.rollback()
        flash('New button added successfully!', 'success')
        return redirect(url_for('toggle'))  
    else:
        print(" web 612 ")
        print("post 613")
        num_buttons = int(request.form['num_buttons'])
        new_button_label = [request.form[f'button{i+1}'] for i in range(num_buttons)]           
        print("620  type(button_labels) ", type(new_button_label))
        print("623 new_button_label   ",new_button_label)
        if not new_button_label:
            flash('No button label provided.', 'danger')
            return jsonify({'error': 'No button label provided.'}), 400
        # Convert string representations of lists to actual lists
        button_labels = ast.literal_eval(settings.button_labels)
        button_states = ast.literal_eval(settings.button_states)
        print(" 631 button_states ", button_states)
        for i in range(len(new_button_label)):
            print(f"633 new_button_label[{i}]",new_button_label[i])
        # Add the new button label and default state
            button_labels.append(new_button_label[i])
            button_states.append('off')
        print("638   new_button_label  ",new_button_label)
        print("642   button_labels  ",button_labels)
        print(" 643 button_states ", button_states)
        # Update the settings object
        settings.button_labels = str(button_labels)
        settings.button_states = str(button_states)
        settings.num_buttons += 1
        print(" 649 db.session.commit()  ")
        try:
            db.session.commit()
        except Exception as e:
            print(f"An error occurred: {e}")
            db.session.rollback()
        flash('New button added successfully!', 'success')
        return redirect(url_for('toggle'))

@app.route('/remove', methods=['POST'])
@custom_login_required
def remove_button():
    user = current_user
    settings = ButtonSettings.query.filter_by(user_id=user.id).first()
    if not settings:
        return jsonify({'error': 'No button settings found for the current user.'}), 404
    data = request.get_json()
    button_label_to_remove = data.get('buttonLabel').strip()
    print("button_label_to_remove:", repr(button_label_to_remove))
    print("type(button_label_to_remove):", type(button_label_to_remove))
    if not button_label_to_remove:
        return jsonify({'error': 'No button label provided.'}), 400
    try:
        button_labels = ast.literal_eval(settings.button_labels)
        button_states = ast.literal_eval(settings.button_states)
    except (SyntaxError, ValueError) as e:
        print("Error parsing button settings:", e)
        return jsonify({'error': 'Error parsing button settings.'}), 500
    print("button_labels:", button_labels)
    print("type(button_labels):", type(button_labels))
    print("button_states:", button_states)
    print("type(button_states):", type(button_states))
    # Strip and compare labels
    button_labels_stripped = [label.strip() for label in button_labels]
    if button_label_to_remove not in button_labels_stripped:
        print("Button label not found:", repr(button_label_to_remove))
        return jsonify({'error': 'Button label not found.'}), 404
    index_to_remove = button_labels_stripped.index(button_label_to_remove)
    print("index_to_remove:", index_to_remove)
    button_labels.pop(index_to_remove)
    button_states.pop(index_to_remove)
    settings.button_labels = str(button_labels)
    settings.button_states = str(button_states)
    settings.num_buttons -= 1
    db.session.commit()
    print("Button removed successfully")
    return jsonify({'message': 'Button removed successfully!', 'num_buttons': settings.num_buttons, 'button_labels': button_labels, 'button_states': button_states}), 200

@app.route('/logout')
def logout():
    print("session[email]  " , session["email"])
    session.pop('email', None)
    print("110")
    logout_user()  # Call Flask-Login's logout function
    print("current_user.is_authenticated:",current_user.is_authenticated)
    print("114")
    flash('Logout successful!', 'success')  # Set flash message
    return redirect(url_for('login'))

mode = 'lldevelopment'
# mode = 'production'
if __name__ == '__main__':
    
    with app.app_context():
        db.create_all()
    if mode == 'development':
        print("797")
        #send_registration_email(bodyh,recipients)
        app.run(port=5050, debug=True)
    else:
        from waitress import serve
        print("802")
        #serve(app)
        # with app.app_context():
        #     print(" 1038")
        #     db.create_all()
        serve(app, port=8070)
