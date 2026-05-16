from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import re

app = Flask(__name__)
app.secret_key = 'your-secret-key-here-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


# Модели базы данных
class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)
    description = db.Column(db.String(200))

    users = db.relationship('User', backref='role', lazy=True)


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(50), nullable=False, unique=True)
    password_hash = db.Column(db.String(200), nullable=False)
    surname = db.Column(db.String(50))
    name = db.Column(db.String(50), nullable=False)
    patronymic = db.Column(db.String(50))
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# Функции валидации
def validate_login(login):
    if not login or len(login) < 5:
        return False, "Логин должен содержать не менее 5 символов"
    if not re.match(r'^[a-zA-Z0-9]+$', login):
        return False, "Логин может содержать только латинские буквы и цифры"
    return True, ""


def validate_password(password):
    if not password:
        return False, "Пароль не может быть пустым"
    if len(password) < 8:
        return False, "Пароль должен содержать не менее 8 символов"
    if len(password) > 128:
        return False, "Пароль должен содержать не более 128 символов"
    if not re.search(r'[A-ZА-Я]', password):
        return False, "Пароль должен содержать хотя бы одну заглавную букву"
    if not re.search(r'[a-zа-я]', password):
        return False, "Пароль должен содержать хотя бы одну строчную букву"
    if not re.search(r'[0-9]', password):
        return False, "Пароль должен содержать хотя бы одну цифру"
    if not re.match(r'^[a-zA-Zа-яА-Я0-9~!?@#$%^&*_\-+()\[\]{}><\/\\|"\'. ,:;]+$', password):
        return False, "Пароль содержит недопустимые символы"
    if ' ' in password:
        return False, "Пароль не должен содержать пробелов"
    return True, ""


def validate_name_field(value, field_name):
    if not value or not value.strip():
        return False, f"Поле '{field_name}' не может быть пустым"
    return True, ""


# Декоратор для проверки аутентификации
def login_required(f):
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('Пожалуйста, войдите в систему для доступа к этой странице', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

def is_admin():
    user = User.query.get(session['user_id'])
    return user and user.role and user.role.name == 'admin'

# Маршруты аутентификации
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login = request.form.get('login')
        password = request.form.get('password')

        user = User.query.filter_by(login=login).first()

        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['user_name'] = f"{user.surname or ''} {user.name}".strip()
            flash('Вы успешно вошли в систему', 'success')
            return redirect(url_for('index'))
        else:
            flash('Неверный логин или пароль', 'danger')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('index'))


@app.route('/change-password', methods=['GET', 'POST'])
@login_required

def change_password():
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        user = User.query.get(session['user_id'])
        errors = {}

        if not check_password_hash(user.password_hash, old_password):
            errors['old_password'] = "Неверный пароль"

        is_valid, msg = validate_password(new_password)
        if not is_valid:
            errors['new_password'] = msg

        if new_password != confirm_password:
            errors['confirm_password'] = "Пароли не совпадают"

        if errors:
            return render_template('change_password.html', errors=errors)

        user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        flash('Пароль успешно изменен', 'success')
        return redirect(url_for('index'))

    # Для GET-запроса передаём пустой словарь errors
    return render_template('change_password.html', errors={})

# Основные маршруты CRUD
@app.route('/')
@app.route('/')
def index():
    users = User.query.all()

    current_user = None
    is_admin_user = False

    if 'user_id' in session:
        current_user = User.query.get(session['user_id'])
        if current_user and current_user.role:
            is_admin_user = current_user.role.name == 'admin'

    return render_template(
        'index.html',
        users=users,
        is_admin_user=is_admin_user
    )


@app.route('/user/<int:user_id>')
def view_user(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('user_view.html', user=user)


@app.route('/user/create', methods=['GET', 'POST'])
@login_required
def create_user():
    if not is_admin():
        flash('Только администратор может создавать пользователей', 'danger')
        return redirect(url_for('index'))
    
    roles = Role.query.all()

    if request.method == 'POST':
        login = request.form.get('login', '').strip()
        password = request.form.get('password', '')
        surname = request.form.get('surname', '').strip() or None
        name = request.form.get('name', '').strip()
        patronymic = request.form.get('patronymic', '').strip() or None
        role_id = request.form.get('role_id')
        role_id = int(role_id) if role_id and role_id != '' else None

        errors = {}

        # Валидация
        is_valid, msg = validate_login(login)
        if not is_valid:
            errors['login'] = msg
        elif User.query.filter_by(login=login).first():
            errors['login'] = "Пользователь с таким логином уже существует"

        is_valid, msg = validate_password(password)
        if not is_valid:
            errors['password'] = msg

        is_valid, msg = validate_name_field(name, "Имя")
        if not is_valid:
            errors['name'] = msg

        if errors:
            return render_template('user_form.html', user=None, roles=roles,
                                   form_data=request.form, errors=errors, is_edit=False)

        # Создание пользователя
        user = User(
            login=login,
            password_hash=generate_password_hash(password),
            surname=surname,
            name=name,
            patronymic=patronymic,
            role_id=role_id
        )

        try:
            db.session.add(user)
            db.session.commit()
            flash('Пользователь успешно создан', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при создании пользователя: {str(e)}', 'danger')
            return render_template('user_form.html', user=None, roles=roles,
                                   form_data=request.form, errors=errors, is_edit=False)

    return render_template('user_form.html', user=None, roles=roles,
                           form_data={}, errors={}, is_edit=False)


@app.route('/user/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    roles = Role.query.all()

    if request.method == 'POST':
        surname = request.form.get('surname', '').strip() or None
        name = request.form.get('name', '').strip()
        patronymic = request.form.get('patronymic', '').strip() or None
        role_id = request.form.get('role_id')
        role_id = int(role_id) if role_id and role_id != '' else None

        errors = {}

        is_valid, msg = validate_name_field(name, "Имя")
        if not is_valid:
            errors['name'] = msg

        if errors:
            return render_template('user_form.html', user=user, roles=roles,
                                   form_data=request.form, errors=errors, is_edit=True)

        user.surname = surname
        user.name = name
        user.patronymic = patronymic
        user.role_id = role_id

        try:
            db.session.commit()
            flash('Пользователь успешно обновлён', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при обновлении пользователя: {str(e)}', 'danger')
            return render_template('user_form.html', user=user, roles=roles,
                                   form_data=request.form, errors=errors, is_edit=True)

    form_data = {
        'surname': user.surname or '',
        'name': user.name,
        'patronymic': user.patronymic or '',
        'role_id': str(user.role_id) if user.role_id else ''
    }
    return render_template('user_form.html', user=user, roles=roles,
                           form_data=form_data, errors={}, is_edit=True)


@app.route('/user/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    user_to_delete = User.query.get_or_404(user_id)
    current_user = User.query.get(session['user_id'])

    # Проверка прав: только админ или сам себя
    if not is_admin() and user_to_delete.id != current_user.id:
        flash('Вы можете удалить только себя или должны быть администратором', 'danger')
        return redirect(url_for('index'))

    # Запрет удаления последнего администратора
    if user_to_delete.role and user_to_delete.role.name == 'admin':
        admin_count = User.query.join(Role).filter(Role.name == 'admin').count()

        if admin_count <= 1:
            flash('Нельзя удалить последнего администратора', 'danger')
            return redirect(url_for('index'))

    try:
        db.session.delete(user_to_delete)
        db.session.commit()

        # Если пользователь удалил сам себя → разлогинить
        if user_to_delete.id == current_user.id:
            session.clear()
            flash('Ваш аккаунт удалён', 'info')
            return redirect(url_for('index'))

        flash('Пользователь успешно удалён', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при удалении пользователя: {str(e)}', 'danger')

    return redirect(url_for('index'))


# Инициализация базы данных
def init_db():
    with app.app_context():
        db.drop_all()
        db.create_all()

        # Создание ролей
        roles = [
            Role(name='admin', description='Полный доступ ко всем функциям системы'),
            Role(name='user', description='Обычный пользователь с базовыми правами'),
            Role(name='manager', description='Менеджер с расширенными правами'),
            Role(name='guest', description='Гостевой доступ с ограничениями')
        ]

        for role in roles:
            db.session.add(role)

        db.session.commit()

        # Создание тестового пользователя
        test_user = User(
            login='admin',
            password_hash=generate_password_hash('Admin123!'),
            surname='Иванов',
            name='Админ',
            patronymic='Админович',
            role_id=1
        )
        db.session.add(test_user)
        db.session.commit()

        print("База данных инициализирована")


if __name__ == '__main__':
    init_db()
    app.run(debug=True)