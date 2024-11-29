from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import re

def extract_number_before_keyword(page_content, keyword):
    # Chercher une séquence de chiffres juste avant le mot-clé
    match = re.search(r"(\d+)\s+" + re.escape(keyword), page_content)
    if match:
        return match.group(1)
    return "N/A"

app = Flask(__name__)
app.secret_key = "SECRET"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///stole_users.db'
db = SQLAlchemy(app)

# Modèle utilisateur
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Route d'accueil
@app.route('/home')
def home():
    username = session.get('username') or request.cookies.get('username')
    if not username:
        return redirect(url_for('login'))
    if username == 'admin':
        return "Bienvenue, Admin !"
    print(f"L'utilisateur {username} est connecté.")
    return render_template('home.html', username=username)

# Route de connexion
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Vérification de l'utilisateur
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['username'] = username  # Session utilisateur
            response = make_response(redirect(url_for('home')))
            response.set_cookie('username', username, max_age=60*60*24, httponly=True)
            print(f"Utilisateur {username} connecté avec succès.")
            return response
        else:
            flash("Nom d'utilisateur ou mot de passe incorrect.")
            return redirect(url_for('login'))
    return render_template('login.html')

# Route d'inscription
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            flash("Le nom d'utilisateur est déjà pris.")
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password, method='sha256')  # Hachage du mot de passe
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        print(f"Nouvel utilisateur inscrit : {username}.")
        return redirect(url_for('login'))
    return render_template('register.html')

# Route de déconnexion
@app.route('/logout')
def logout():
    session.pop('username', None)
    response = make_response(redirect(url_for('index')))
    response.delete_cookie('username')
    return response

# Exemple pour Krakozia (utilisation d'un cookie)
@app.route('/krakozia')
def krakozia():
    username = request.cookies.get('username')
    if not username:
        return redirect(url_for('login'))
    return render_template('krakozia.html', username=username)

# Route d'accueil
@app.route('/')
def index():
    return render_template('index.html')

# Exemple avec récupération de contenu externe
@app.route('/nombre')
def nombre():
    external_url = 'https://www.krakozia.fr'
    chrome_options = Options()
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    driver = webdriver.Chrome(options=chrome_options)
    
    try:
        driver.get(external_url)
        driver.implicitly_wait(30)
        page_content = driver.page_source
        driver.quit()

        nombre = extract_number_before_keyword(page_content, "Pirates en ligne")
        
        return jsonify({"nombre": nombre})        
    except Exception as e:
        driver.quit()
        flash('Impossible de charger la page externe.')
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)