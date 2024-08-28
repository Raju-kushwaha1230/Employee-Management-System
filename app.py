from flask import Flask , render_template , request, redirect, url_for, flash  , session, abort

from flask_wtf import   FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired , Length
from flask_bcrypt import Bcrypt
from forms import ProfileForm
from functools import wraps
from decimal import Decimal
import mysql.connector

app = Flask(__name__)
app.secret_key = 'your_secret_key'
bcrypt = Bcrypt(app)

 
con = mysql.connector.connect(
     host = 'localhost',
     user = 'root',
     password = 'mighty@098',
     database = 'emp'
     
)
cursor = con.cursor(buffered=True)

class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(),Length(min=4, max=50)])
    password = PasswordField('Password',validators=[DataRequired(), Length(min=6)])
    employee_id = StringField('Employee ID', validators=[DataRequired()])
    role = SelectField('Role', choices=[('Employee','Employee'),('Admin','Admin')])
    submit = SubmitField('Sign Up')
    
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=50)])
    password = PasswordField('Password', validators=[DataRequired()])
    # role = SelectField('Role', choices=[('Employee','Employee'),('Admin','Admin')])
    submit = SubmitField('Login')

 
def check_employee(employee_id):
     sql = 'SELECT * FROM employees WHERE id=%s'
     cursor.execute(sql , (employee_id,))
     return cursor.rowcount == 1
 
### role based access control 
def role_required(role):
    def wrapper(func):
        @wraps(func)
        def decorated_view(*args, **kwargs):
            if 'username' not in session:
                abort(404)
            username= session['username']
            user_role = session.get('role')
            if user_role != role:
                abort(404)
            return func(*args,**kwargs)
        return decorated_view
    return wrapper

 
@app.route('/', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        employee_id = form.employee_id.data
        role = form.role.data
        
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

        try:
            sql = 'INSERT INTO users (username,password_hash,employee_id, role) VALUES (%s,%s,%s,%s)'
            cursor.execute(sql, (username, password_hash,employee_id, role))
            con.commit()
            
            session['username'] = username
            session['role'] = role
            
            flash('Sign up successful! Please log in.')
            return redirect(url_for('login'))
        except mysql.connector.Error as err:
            con.rollback()
            flash(f'Error:{err}')
            return render_template('signup.html', form=form)
        
    return render_template('signup.html', form=form)
     
     
@app.route('/login', methods =['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username= form.username.data
        password = form.password.data
        # role = form.role.data
        
        
        sql = 'SELECT username,password_hash,employee_id,role FROM users WHERE username=%s'
        cursor.execute(sql,(username,))
        
        result = cursor.fetchone()
        if result is None:
            flash("INvalid username and password.","danger")
            return redirect(url_for('login'))
        
        db_username,password_hash,employee_id, user_role = result
        
        if  bcrypt.check_password_hash(password_hash,password):
            session['username'] = db_username
            session['role'] = user_role
            # session['role'] = role
                    

            flash(f'Welcome, {db_username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password.",'danger')
        
    return render_template('login.html',form=form)

@app.route('/dashboard')
def dashboard():
    if 'username'  in session:
        username = session['username']
        role = session['role']
        
        sql = 'SELECT employee_id FROM users WHERE username=%s'
        cursor.execute(sql,(username,))
        employee_id = cursor.fetchone()

        if employee_id:
            employee_id = employee_id[0]
            sql = 'SELECT * FROM employees WHERE id=%s'
            cursor.execute(sql,(employee_id,))
            employee = cursor.fetchone()
        else:
            employee = None
        
        return render_template('dashboard.html', username=username, role=role, employee=employee)
    return redirect(url_for('login'))
    
    if 'username' not in session:
        flash("wronge password and username")
        return redirect(url_for('login'))

    
    username = session['username']
    role = session['role']
    sql = 'SELECT employee_id FROM users WHERE username=%s'
    cursor.execute(sql, (username,))
    employee_id = cursor.fetchone()[0]
    
    sql = 'SELECT role FROM users WHERE username=%s'
    cursor.execute(sql,(role,))
    user_role = cursor.fetchone()
    
    sql = 'SELECT * FROM employees WHERE id=%s'
    cursor.execute(sql, (employee_id,))
    employee = cursor.fetchone()
    
    return render_template('dashboard.html', employee=employee)

@app.route('/admin')
@role_required('Admin')
def admin_dashboard():
    cursor.execute('SELECT * FROM employees')
    employees  = cursor.fetchall()
    return render_template('index.html', employees = employees)
    return render_template('index.html')


@app.route('/profile', methods=['GET','POST'])
def profile():
    if 'username' not in session:
        flash('Please log in to access your account')
        return redirect(url_for('login'))
    
    username = session['username']
    form  = ProfileForm()

    if form.validate_on_submit():
        new_password = form.new_password.data
        if new_password:
            password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
            sql = 'UPDATE users SET password_hash=%s WHERE username=%s'
            cursor.execute(sql,(password_hash,username))
            con.commit()
            flash('profile updated successfully')
    
    sql = 'SELECT employee_id FROM users WHERE username=%s'
    cursor.execute(sql,(username,))
    employee_id = cursor.fetchone()[0]

    sql = 'SELECT * FROM employees WHERE id=%s'
    cursor.execute(sql,(employee_id,))
    employee = cursor.fetchone()

    form.username.data = username
    form.employee_id.data = employee_id

    return render_template('profile.html',form=form, employee=employee)




@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('role',None)

    flash('You have been logged out.')
    return redirect(url_for('login'))
    
@app.errorhandler(403)
def forbidden(error):
    return render_template('403.html'),403
    

@app.route('/index')
def index():
     cursor.execute('SELECT * FROM employees')
     employees  = cursor.fetchall()
     return render_template('index.html', employees = employees)

@app.route('/add', methods = ['POST'])
def add_employee():
    Id = request.form['id']
    Name = request.form['name']
    Post = request.form['post']
    Salary = request.form['salary']

    if check_employee(Id):
        flash("EMployee already exists . Please try again.")
        return redirect(url_for('index'))
    
    
    try :
        while cursor.nextset():
            pass
        sql = 'INSERT INTO employees (id, name, position, salary) VALUES(%s, %s, %s, %s)'
        data = (Id, Name, Post, Salary)
        cursor.execute(sql, data)
        con.commit()
        flash("Employee Added Successfully")
    except mysql.connector.Error as err:
        flash(f"Error : {err}")
        con.rollback()
    
    return redirect(url_for('index'))

    
@app.route('/delete_employee/<employee_id>', methods = ['GET', 'POST'])
def delete_employee(employee_id):
    try:
        cursor.execute('DELETE FROM users WHERE employee_id=%s', (employee_id,))
        con.commit()

        cursor.execute('DELETE FROM employees WHERE id=%s',(employee_id,))
        con.commit()

        flash('Employee deleted successfully')
    except mysql.connector.Error as err:
        con.rollback()
        flash(f'Error:{err}')
        return redirect(url_for('index'))

    # sql = 'DELETE FROM employees WHERE id = %s'
    # if not check_employee(id):
    #     flash("Employee doesn't exists. Please try again ")
    #     return redirect(url_for('login'))

    # try:
    #     cursor.execute(sql, (id,))
    #     con.commit()
    #     flash("Employee removed successfully")
    # except mysql.connector.Error as err:
    #     flash(f"Error: {err}"
    #     con.rollback()
    return redirect(url_for('index'))

    
@app.route('/promote', methods = ['POST'])
def promote_employee():
    Id = request.form['id']
    Amount = Decimal(request.form['amount'])

    if not check_employee(Id):
        flash("Employee doesn't exists, please try again")
        return redirect(url_for('index'))
    
    try:
        sql_select = 'SELECT salary FROM employees WHERE id=%s'
        cursor.execute(sql_select,(Id,))
        result = cursor.fetchone()
        if result is None:
            flash('Employee salary not found')
            return redirect(url_for('index'))
        current_salary = result[0]
        new_salary = current_salary + Amount

        sql_update = 'UPDATE employees SET salary=%s WHERE id=%s'
        cursor.execute(sql_update,(new_salary, Id,))
        con.commit()
        flash("Employee promoted successfully")
    except mysql.connector.Error as err:
        con.rollback()
        flash(f'Error:{err}')
        
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)

