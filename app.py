import os
import subprocess
from subprocess import Popen, PIPE
from subprocess import check_output
from flask import Flask, render_template, request
import json
from flask import session, redirect,url_for
from passlib.hash import sha256_crypt
from flask_wtf.csrf import CSRFProtect
import re
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime


base_dir = os.path.dirname(os.path.abspath(__file__))
database_file = "sqlite:///{}".format(os.path.join(base_dir, "instance/spellcheck.db"))
print (database_file)

app = Flask(__name__)
#Set secret key for session management
app.secret_key ='kfsdjfwurwrposdjodsjfoue90fdfdfdfdfds'

#Set DB URI
app.config["SQLALCHEMY_DATABASE_URI"] = database_file
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)



#Enable CSRFProtect to again CSRF Attack
csrf = CSRFProtect(app)

# Disable CSRF for testing
#app.config['WTF_CSRF_METHODS'] = [] 

#Define user model
class User(db.Model):
    __tablename__ = 'users'
    username = db.Column(db.String(20), unique=True, nullable=False, primary_key=True)
    password = db.Column(db.String(86), nullable=False)
    twofa = db.Column(db.String(11), nullable=False)
    role = db.Column(db.String(6),nullable = True)
    #histories = db.relationship('History', backref = 'user', lazy = True)
    #queries = db.relationship('Query', backref = 'user', lazy = True)


    def __repr__(self):
        return "<User %r %r %r>" % (self.username, self.password, self.twofa)

class History(db.Model):
    __tablename__ = 'histories'
    logid = db.Column(db.Integer, nullable=False, autoincrement = True, primary_key=True)  
    loginTime = db.Column(db.DateTime, nullable=False)
    logoutTime = db.Column(db.DateTime, nullable=True)
    username = db.Column(db.String(20), nullable=False)
    #username = db.Column(db.String(20), nullable=False, db.ForeignKey('user.username'))

    def __repr__(self):
        return "<History %r %r %r %r>" % (self.logid, self.loginTime, self.logoutTime, self.username)

class Query(db.Model):
    __tablename__ = 'queries'
    queryid = db.Column(db.Integer, nullable=False, autoincrement = True, primary_key=True)
    querytext = db.Column(db.String(4000), nullable=False)
    queryresult = db.Column(db.String(4000), nullable=False)
    username = db.Column(db.String(20), nullable=False)
    #username = db.Column(db.String(20), nullable=False, db.ForeignKey('user.username'))

    def __repr__(self):
        return "<Query %r %r %r %r>" % (self.queryid, self.querytext, self.queryresult, self.username)


#Index page redirects to login page
@app.route('/')
def index():
    session.clear()    
    return redirect(url_for('login'))

#Register page
@app.route('/register', methods =['POST','GET'])
def register():
    if request.method =='POST':
        result = ""
        #Using lower() to avoid case sensetive for user name
        username = request.form['uname'].lower()
        pwordInput = request.form['pword']
        fa = request.form['2fa']

        user = User.query.filter_by(username=username).first()

        #Validate the inputs
        if (re.match (r"^([A-Za-z0-9]){3,20}$",username) and re.match(r"^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{8,}$",pwordInput) and (True if (fa =="") else re.match(r"^\d{11}",fa))):
            #If user existed, then return failure
            if (user is not None):
                result = "failure"
            else: 
                #Hash password by sha256
                password = sha256_crypt.using(rounds=324333).hash(pwordInput)
                
                #Save password into a dictionary and then save in a file
                user = User(username=username,password=password,twofa = fa)
                db.session.add(user)
                db.session.commit()
                result = "success"
        else:
            result = "Username, password or 2FA format doesn't meet the requirement."

        return render_template ('register.html', result = result)

    if request.method == 'GET':
        session.clear()
        return render_template ('register.html')


@app.route('/login', methods =['POST','GET'])
def login():
    if request.method =='POST':
        result=""
        #Using lower() to avoid case sensetive for user name
        username = request.form['uname'].lower()
        password = request.form['pword']
        fa = request.form['2fa']
        

        user = User.query.filter_by(username=username).first()

        #Validate the inputs
        if (re.match (r"^((?!(<script(\s|\S)*?<\/script>)|(<style(\s|\S)*?<\/style>)|(<!--(\s|\S)*?-->)|(<\/?(\s|\S)*?>)).)*$",username) and re.match(r"^((?!(<script(\s|\S)*?<\/script>)|(<style(\s|\S)*?<\/style>)|(<!--(\s|\S)*?-->)|(<\/?(\s|\S)*?>)).)*$",password) and (True if (fa =="") else re.match(r"^((?!(<script(\s|\S)*?<\/script>)|(<style(\s|\S)*?<\/style>)|(<!--(\s|\S)*?-->)|(<\/?(\s|\S)*?>)).)*$",fa))):      
            if (user is not None):
                #Verify the password            
                if sha256_crypt.verify(password, user.password):
                    if (user.twofa==fa ):                    
                        
                        #Get UTC datetime
                        timestamp = datetime.utcnow()
                        #Set session if login success
                        session['logged_in'] = username
                        #Set session loginTime for later query
                        session['loginTime'] =timestamp.isoformat()
    
                        log = History(username=username,loginTime = timestamp)
                        db.session.add(log)
                        
                        db.session.commit()
                        result = "success"                    
                    else:
                        result = "Two-factor failure"
                else:
                    result = "Incorrect"
            else:
                result = "Incorrect"
        else:
            result = "Username, password or 2FA format doesn't meet the requirement."

        return render_template('login.html', result=result)

    if request.method == 'GET':
        return render_template ('login.html')


@app.route('/spell_check', methods =['POST','GET'])
def spell_check():
    #Convert session loginTime to datetime format for comparison
    currentLoginTime = datetime.strptime(session['loginTime'], '%Y-%m-%dT%H:%M:%S.%f')

    currentlog= History.query.filter_by(loginTime = currentLoginTime).first()

    if(session.get('logged_in')== currentlog.username):   
        #Get current work directory
        cpath = os.getcwd()
        
        if request.method =='POST':
            textout = request.form['inputtext']
            textfile = open("./static/text.txt","w")
            textfile.writelines(textout)
            textfile.close()           
            tmp=subprocess.check_output([cpath+'/static/a.out',cpath+'/static/text.txt', cpath+'/static/wordlist.txt']).decode("utf-8")
            misword = tmp.replace("\n",", ")[:-2]
            querylog = Query(querytext=textout,queryresult = misword, username = currentlog.username)
            db.session.add(querylog)
            db.session.commit()
            return render_template ('spell_check.html', misword = misword, textout=textout)
        if request.method =='GET':
            return render_template ('spell_check.html')
    else:
        return redirect(url_for('login'))
     

    
@app.route('/logout')
def logout():
    timestamp = datetime.utcnow()
    #Convert session loginTime to datetime format for comparison
    currentLoginTime = datetime.strptime(session['loginTime'], '%Y-%m-%dT%H:%M:%S.%f')
    currentlog= History.query.filter_by(loginTime = currentLoginTime).first()
    currentlog.logoutTime = timestamp
    db.session.add(currentlog)
    db.session.commit()

    session.clear()
    return redirect(url_for('login'))

if __name__ == "__main__":
    
    app.run(debug=True)
