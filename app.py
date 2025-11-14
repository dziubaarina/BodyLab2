from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField, IntegerField, HiddenField
from wtforms.fields import DateField, TimeField
from wtforms.validators import DataRequired, Email, EqualTo, NumberRange, InputRequired
from config import Config
from functools import wraps
from datetime import date, time, datetime
from sqlalchemy import Date, Time, or_
import sys
import click  # Import dla komend CLI

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = "login"


# === MODELE BAZY DANYCH ===

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    # --- NOWY SYSTEM RÓL ---
    # Role: 'user' (użytkownik), 'trainer' (trener), 'admin' (menedżer)
    role = db.Column(db.String(20), nullable=False, default='user')

    experience_notes = db.Column(db.Text, nullable=True)  # Notatki o doświadczeniu

    # Relacje
    sessions_taught = db.relationship('TrainingSession', back_populates='trainer', lazy='dynamic')
    bookings = db.relationship('Booking', back_populates='user', lazy='dynamic')
    messages_sent = db.relationship('Message', foreign_keys='Message.sender_id', back_populates='sender',
                                    lazy='dynamic')
    messages_received = db.relationship('Message', foreign_keys='Message.recipient_id', back_populates='recipient',
                                        lazy='dynamic')

    # Właściwości ułatwiające sprawdzanie ról w szablonach
    @property
    def is_admin(self):
        return self.role == 'admin'

    @property
    def is_trainer(self):
        return self.role == 'trainer'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class TrainingSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    session_type = db.Column(db.String(20), nullable=False, default='Grupowy')
    description = db.Column(db.Text, nullable=True)
    date = db.Column(db.Date, nullable=False)
    start_time = db.Column(db.Time, nullable=False)
    duration_minutes = db.Column(db.Integer, nullable=False, default=60)
    price = db.Column(db.Integer, nullable=False, default=0)
    max_participants = db.Column(db.Integer, nullable=False, default=10)
    trainer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    trainer = db.relationship('User', back_populates='sessions_taught')
    bookings = db.relationship('Booking', back_populates='session', lazy='dynamic', cascade="all, delete-orphan")

    @property
    def current_participants(self):
        return self.bookings.count()

    @property
    def is_full(self):
        return self.bookings.count() >= self.max_participants


class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_id = db.Column(db.Integer, db.ForeignKey('training_session.id'), nullable=False)

    user = db.relationship('User', back_populates='bookings')
    session = db.relationship('TrainingSession', back_populates='bookings')

    __table_args__ = (db.UniqueConstraint('user_id', 'session_id', name='_user_session_uc'),)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    sender = db.relationship('User', foreign_keys=[sender_id], back_populates='messages_sent')
    recipient = db.relationship('User', foreign_keys=[recipient_id], back_populates='messages_received')


class Workout(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.String(10), nullable=False)
    start_time = db.Column(db.String(5), nullable=False)
    duration = db.Column(db.String(10), nullable=False)
    notes = db.Column(db.Text)
    user = db.relationship('User', backref=db.backref('workouts', lazy=True))


class Exercise(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    workout_id = db.Column(db.Integer, db.ForeignKey('workout.id'), nullable=False)
    body_part = db.Column(db.String(50), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    sets = db.Column(db.Integer, nullable=False)
    reps = db.Column(db.Integer, nullable=False)
    workout = db.relationship('Workout', backref=db.backref('exercises', lazy=True))


# === FORMULARZE ===

class RegisterForm(FlaskForm):
    username = StringField("Nazwa użytkownika", validators=[DataRequired()])
    email = StringField("Email np.user@example.com", validators=[DataRequired(), Email()])
    password = PasswordField("Hasło",
                             validators=[DataRequired(), EqualTo("password2", message="Hasła muszą być takie same!")])
    password2 = PasswordField("Powtórz hasło", validators=[DataRequired()])
    submit = SubmitField("Zarejestruj się")


class LoginForm(FlaskForm):
    email = StringField("Email np.user@example.com", validators=[DataRequired(), Email()])
    password = PasswordField("Hasło", validators=[DataRequired()])
    submit = SubmitField("Zaloguj się")


class WorkoutForm(FlaskForm):
    date = StringField("Data", validators=[DataRequired()])
    start_time = StringField("Godzina rozpoczęcia", validators=[DataRequired()])
    duration = StringField("Czas trwania", validators=[DataRequired()])
    notes = TextAreaField("Notatki")
    submit = SubmitField("Dodaj trening")


class SessionForm(FlaskForm):
    title = StringField("Tytuł zajęć", validators=[DataRequired()])
    session_type = SelectField("Typ zajęć", choices=[('Grupowy', 'Grupowy'), ('Indywidualny', 'Indywidualny')],
                               validators=[DataRequired()])
    description = TextAreaField("Opis zajęć (opcjonalnie)")
    date = DateField("Data (RRRR-MM-DD)", validators=[DataRequired()], format='%Y-%m-%d')
    start_time = TimeField("Godzina rozpoczęcia (GG:MM)", validators=[DataRequired()], format='%H:%M')
    duration_minutes = IntegerField("Czas trwania (w minutach)",
                                    validators=[DataRequired(), NumberRange(min=30, max=240)], default=60)
    price = IntegerField("Cena (w zł)", validators=[DataRequired(), NumberRange(min=0)], default=0)
    max_participants = IntegerField("Limit miejsc", validators=[DataRequired(), NumberRange(min=1)], default=10)

    # Pole wyboru trenera, widoczne tylko dla admina
    trainer = SelectField("Prowadzący Trener", coerce=int, validators=[InputRequired()])
    submit = SubmitField("Zapisz zajęcia")

    def __init__(self, *args, **kwargs):
        super(SessionForm, self).__init__(*args, **kwargs)
        # Dynamiczne wypełnienie listy trenerów (rolą 'trainer' lub 'admin')
        self.trainer.choices = [(u.id, u.username) for u in
                                User.query.filter(or_(User.role == 'trainer', User.role == 'admin')).all()]


class MoveBookingForm(FlaskForm):
    # Lista rozwijana z dostępnymi sesjami
    new_session = SelectField("Wybierz nowe zajęcia", coerce=int, validators=[DataRequired()])
    submit = SubmitField("Przenieś rezerwację")

    def __init__(self, original_session_id=None, *args, **kwargs):
        super(MoveBookingForm, self).__init__(*args, **kwargs)
        today = date.today()
        # Wypełnij listę tylko nadchodzącymi sesjami, które NIE SĄ pełne
        # i nie są tą samą sesją, z której przenosimy
        self.new_session.choices = [
            (s.id, f"{s.title} ({s.date}) - {s.current_participants}/{s.max_participants} miejsc")
            for s in TrainingSession.query.filter(
                TrainingSession.date >= today,
                TrainingSession.id != original_session_id
            ).all() if not s.is_full
        ]


# === DEKORATORY I FUNKCJE POMOCNICZE ===

@login_manager.user_loader
def load_user(user_id):
    # Używamy db.session.get() zamiast User.query.get()
    return db.session.get(User, int(user_id))


# Dekorator tylko dla roli 'admin' (Menedżer)
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("Dostęp do tej strony wymaga uprawnień Menedżera.", "danger")
            return redirect(url_for('index'))
        return f(*args, **kwargs)

    return decorated_function


# Dekorator dla ról 'admin' LUB 'trainer' (Trenerzy i Menedżerowie)
def trainer_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or (not current_user.is_admin and not current_user.is_trainer):
            flash("Dostęp do tej strony wymaga uprawnień Trenera.", "danger")
            return redirect(url_for('index'))
        return f(*args, **kwargs)

    return decorated_function


# === LISTY ĆWICZEŃ (STARY SYSTEM) ===
EXERCISE_SUGGESTIONS = [
    "Przysiady ze sztangą", "Przysiady bułgarskie", "Prostowanie nóg w siadzie", "Martwy ciąg",
    "Wiosłowanie hantlami", "Ściąganie drążka wyciągu", "Podciąganie na drążku", "Wyciskanie sztangi leżąc",
    "Rozpiętki ze sztangielkami", "Pompki", "Pompki na poręczach", "Wyciskanie hantli nad głowę",
    "Wyciskanie francuskie", "Uginanie ramion ze sztangą", "Face pull", "Plank", "Russian twist",
    "Unoszenie nóg w zwisie", "Burpees", "Dipy na poręczach"
]
EXERCISE_TO_BODY_PART = {
    "Przysiady ze sztangą": "Nogi", "Przysiady bułgarskie": "Nogi", "Prostowanie nóg w siadzie": "Nogi",
    "Martwy ciąg": "Plecy", "Wiosłowanie hantlami": "Plecy", "Ściąganie drążka wyciągu": "Plecy",
    "Podciąganie na drążku": "Plecy", "Wyciskanie sztangi leżąc": "Klatka", "Rozpiętki ze sztangielkami": "Klatka",
    "Pompki": "Klatka", "Pompki na poręczach": "Klatka", "Wyciskanie hantli nad głowę": "Barki",
    "Wyciskanie francuskie": "Triceps", "Uginanie ramion ze sztangą": "Biceps", "Face pull": "Barki",
    "Plank": "Brzuch", "Russian twist": "Brzuch", "Unoszenie nóg w zwisie": "Brzuch",
    "Burpees": "Całe ciało", "Dipy na poręczach": "Triceps"
}


# === TRASY PUBLICZNE ===

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/cennik")
def pricing():
    return render_template("pricing.html")


@app.route("/infrastruktura")
def infrastructure():
    return render_template("infrastructure.html")


@app.route("/faq")
def faq():
    return render_template("faq.html")


@app.route("/announcements")
def announcements():
    posts = [
        {"title": "Nowy grafik od 1 kwietnia!", "date": "28.03.2025", "content": "Wprowadzamy nowe zajęcia...",
         "badge": "light "},
        {"title": "Bezpłatny tydzień próbny!", "date": "12.11.2025", "content": "Przyjdź od 17 do 23 listopada...",
         "badge": "light"},
        {"title": "Zamknięte 24-26 grudnia", "date": "20.12.2025", "content": "Święta = regeneracja...",
         "badge": "light"},
        {"title": "Poranne cardio 6:30", "date": "13.11.2025", "content": "Nowe zajęcia: CARDIO START...",
         "badge": "light"}
    ]
    return render_template("announcements.html", posts=posts)


# === TRASY LOGOWANIA I REJESTRACJI ===

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash("Ten adres e-mail jest już zajęty. Wybierz inny.", "danger")
            return redirect(url_for("register"))
        existing_username = User.query.filter_by(username=form.username.data).first()
        if existing_username:
            flash("Ta nazwa użytkownika jest już zajęta. Wybierz inną.", "danger")
            return redirect(url_for("register"))

        # Nowi użytkownicy są domyślnie 'user'
        user = User(username=form.username.data, email=form.email.data, role='user')
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash("Konto utworzone! Możesz się zalogować.", "success")
        return redirect(url_for("login"))
    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            # Przekierowanie na podstawie roli
            if user.is_admin:
                return redirect(url_for("admin_dashboard"))
            if user.is_trainer:
                return redirect(url_for("trainer_dashboard"))
            return redirect(url_for("dashboard"))
        flash("Błędny email lub hasło", "danger")
    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


# === TRASY UŻYTKOWNIKA (STARY DZIENNICZEK + NOWY BOOKING) ===

@app.route("/dashboard")
@login_required
def dashboard():
    # Menedżer i Trener są automatycznie wysyłani do swoich paneli
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    if current_user.is_trainer:
        return redirect(url_for('trainer_dashboard'))

    # To jest panel zwykłego użytkownika
    workouts = Workout.query.filter_by(user_id=current_user.id).all()
    return render_template("dashboard.html", user=current_user, workouts=workouts)


@app.route("/add_workout", methods=["GET", "POST"])
@login_required
def add_workout():
    form = WorkoutForm()
    if form.validate_on_submit():
        workout = Workout(
            user_id=current_user.id,
            date=form.date.data,
            start_time=form.start_time.data,
            duration=form.duration.data,
            notes=form.notes.data
        )
        db.session.add(workout)
        db.session.commit()
        # ... (logika dodawania ćwiczeń) ...
        flash("Trening dodany!", "success")
        return redirect(url_for("dashboard"))

    return render_template(
        "add_workout.html",
        form=form,
        exercise_suggestions=EXERCISE_SUGGESTIONS
    )


@app.route("/workout_history")
@login_required
def workout_history():
    workouts = Workout.query.filter_by(user_id=current_user.id).all()
    for workout in workouts:
        workout.exercises = Exercise.query.filter_by(workout_id=workout.id).all()
    return render_template("workout_history.html", workouts=workouts)


@app.route("/workout/<int:workout_id>")
@login_required
def view_workout(workout_id):
    workout = db.session.get(Workout, workout_id)
    if not workout:
        flash("Nie znaleziono takiego treningu.", "danger")
        return redirect(url_for('workout_history'))

    # Admin/Trener może zobaczyć wszystko, użytkownik tylko swoje
    if not (current_user.is_admin or current_user.is_trainer) and workout.user_id != current_user.id:
        flash("Nie masz uprawnień do wyświetlenia tego treningu.", "danger")
        return redirect(url_for('dashboard'))

    exercises = Exercise.query.filter_by(workout_id=workout.id).all()
    return render_template("view_workout.html", workout=workout, exercises=exercises)


# === NOWE TRASY SYSTEMU REZERWACJI (UŻYTKOWNIK) ===

@app.route("/booking", methods=["GET"])
@login_required
def booking():
    today = date.today()
    user_booked_session_ids = {booking.session_id for booking in current_user.bookings.all()}

    sessions_grupowe = TrainingSession.query.filter(
        TrainingSession.date >= today,
        TrainingSession.session_type == 'Grupowy'
    ).order_by(TrainingSession.date, TrainingSession.start_time).all()

    sessions_indywidualne = TrainingSession.query.filter(
        TrainingSession.date >= today,
        TrainingSession.session_type == 'Indywidualny'
    ).order_by(TrainingSession.date, TrainingSession.start_time).all()

    return render_template("booking.html",
                           sessions_grupowe=sessions_grupowe,
                           sessions_indywidualne=sessions_indywidualne,
                           user_booked_session_ids=user_booked_session_ids,
                           today=today)


@app.route("/book_session", methods=["POST"])
@login_required
def book_session():
    session_id = request.form.get('session_id')
    session_to_book = db.session.get(TrainingSession, session_id)

    if not session_to_book:
        flash("Nie znaleziono takich zajęć.", "danger")
        return redirect(url_for('booking'))

    existing_booking = Booking.query.filter_by(user_id=current_user.id, session_id=session_id).first()
    if existing_booking:
        flash("Jesteś już zapisany/a na te zajęcia.", "info")
        return redirect(url_for('booking'))

    if session_to_book.is_full:
        flash("Niestety, na te zajęcia nie ma już wolnych miejsc.", "danger")
        return redirect(url_for('booking'))

    if session_to_book.trainer_id == current_user.id:
        flash("Nie możesz zapisać się na własne zajęcia.", "warning")
        return redirect(url_for('booking'))

    try:
        new_booking = Booking(user_id=current_user.id, session_id=session_id)
        db.session.add(new_booking)
        db.session.commit()
        flash(f"Pomyślnie zapisano na zajęcia: {session_to_book.title}!", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Wystąpił błąd podczas rezerwacji: {e}", "danger")

    return redirect(url_for('booking'))


@app.route("/trainer_profile/<int:trainer_id>")
@login_required
def trainer_profile(trainer_id):
    trainer = db.session.get(User, trainer_id)
    if not trainer or (not trainer.is_admin and not trainer.is_trainer):
        flash("Ten użytkownik nie jest trenerem.", "danger")
        return redirect(url_for('booking'))
    return render_template("trainer_profile.html", trainer=trainer)


# === TRASY MENEDŻERA (ADMIN) ===

@app.route("/admin")
@login_required
@admin_required
def admin_dashboard():
    all_users = User.query.order_by(User.id).all()
    return render_template("admin.html", users=all_users)


@app.route("/admin/edit_user/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def admin_edit_user(user_id):
    # Prosta edycja roli (na przyszłość można rozbudować)
    user_to_edit = db.session.get(User, user_id)
    new_role = request.form.get('role')
    if user_to_edit and new_role in ['user', 'trainer', 'admin']:
        if user_to_edit.id == current_user.id and new_role != 'admin':
            flash("Nie możesz odebrać sobie uprawnień administratora.", "danger")
        else:
            user_to_edit.role = new_role
            db.session.commit()
            flash(f"Zaktualizowano rolę użytkownika {user_to_edit.username} na {new_role}.", "success")
    else:
        flash("Wystąpił błąd podczas edycji użytkownika.", "danger")
    return redirect(url_for('admin_dashboard'))


# === TRASY TRENERA (I MENEDŻERA) ===

@app.route("/trainer")
@login_required
@trainer_required
def trainer_dashboard():
    query = TrainingSession.query
    # Menedżer widzi wszystkie zajęcia
    if not current_user.is_admin:
        # Trener widzi tylko swoje
        query = query.filter_by(trainer_id=current_user.id)

    my_sessions = query.order_by(TrainingSession.date.desc()).all()
    return render_template("trainer_dashboard.html", my_sessions=my_sessions)


@app.route("/create_session", methods=["GET", "POST"])
@login_required
@trainer_required
def create_session():
    form = SessionForm()

    # Jeśli trener, zablokuj pole i ustaw na siebie
    if not current_user.is_admin:
        form.trainer.data = current_user.id

    if form.validate_on_submit():
        try:
            # Prowadzącym jest osoba wybrana z formularza (jeśli admin)
            # lub zalogowany użytkownik (jeśli trener)
            trainer_id_to_assign = form.trainer.data

            new_session = TrainingSession(
                title=form.title.data,
                session_type=form.session_type.data,
                description=form.description.data,
                date=form.date.data,
                start_time=form.start_time.data,
                duration_minutes=form.duration_minutes.data,
                price=form.price.data,
                max_participants=form.max_participants.data,
                trainer_id=trainer_id_to_assign
            )
            db.session.add(new_session)
            db.session.commit()
            flash(f"Pomyślnie utworzono nowe zajęcia: {new_session.title}", "success")
            return redirect(url_for('trainer_dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f"Wystąpił błąd podczas tworzenia zajęć: {e}", "danger")

    if not form.date.data:
        form.date.data = date.today()

    return render_template("create_session.html", form=form, title="Stwórz Nowe Zajęcia")


@app.route("/manage_session/<int:session_id>")
@login_required
@trainer_required
def manage_session(session_id):
    session = db.session.get(TrainingSession, session_id)
    if not session:
        flash("Nie znaleziono takich zajęć.", "danger")
        return redirect(url_for('trainer_dashboard'))

    # Trener może zarządzać tylko swoimi zajęciami (admin może wszystkimi)
    if not current_user.is_admin and session.trainer_id != current_user.id:
        flash("Nie masz uprawnień do zarządzania tymi zajęciami.", "danger")
        return redirect(url_for('trainer_dashboard'))

    return render_template("manage_session.html", session=session)


@app.route("/cancel_booking/<int:booking_id>", methods=["POST"])
@login_required
@trainer_required
def cancel_booking(booking_id):
    booking = db.session.get(Booking, booking_id)
    if not booking:
        flash("Nie znaleziono takiej rezerwacji.", "danger")
        return redirect(url_for('trainer_dashboard'))

    # Sprawdzenie uprawnień (czy to admin lub trener prowadzący te zajęcia)
    session_id = booking.session.id
    if not current_user.is_admin and booking.session.trainer_id != current_user.id:
        flash("Nie masz uprawnień do anulowania tej rezerwacji.", "danger")
        return redirect(url_for('manage_session', session_id=session_id))

    try:
        db.session.delete(booking)
        db.session.commit()
        flash(f"Pomyślnie anulowano rezerwację dla {booking.user.username}.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Wystąpił błąd podczas anulowania: {e}", "danger")

    return redirect(url_for('manage_session', session_id=session_id))


@app.route("/move_booking/<int:booking_id>", methods=["GET", "POST"])
@login_required
@trainer_required
def move_booking(booking_id):
    booking_to_move = db.session.get(Booking, booking_id)
    if not booking_to_move:
        flash("Nie znaleziono takiej rezerwacji.", "danger")
        return redirect(url_for('trainer_dashboard'))

    session = booking_to_move.session
    user = booking_to_move.user

    # Sprawdzenie uprawnień
    if not current_user.is_admin and session.trainer_id != current_user.id:
        flash("Nie masz uprawnień do zarządzania tą rezerwacją.", "danger")
        return redirect(url_for('trainer_dashboard'))

    form = MoveBookingForm(original_session_id=session.id)

    if form.validate_on_submit():
        new_session_id = form.new_session.data
        new_session = db.session.get(TrainingSession, new_session_id)

        if not new_session:
            flash("Wybrano nieprawidłowe zajęcia docelowe.", "danger")
        elif new_session.is_full:
            flash("Nowe zajęcia są już pełne!", "danger")
        elif Booking.query.filter_by(user_id=user.id, session_id=new_session_id).first():
            flash(f"Użytkownik {user.username} jest już zapisany na wybrane zajęcia.", "warning")
        else:
            try:
                # Aktualizujemy starą rezerwację na nową sesję
                booking_to_move.session_id = new_session_id
                db.session.commit()
                flash(f"Pomyślnie przeniesiono {user.username} na zajęcia {new_session.title}.", "success")
                return redirect(url_for('manage_session', session_id=session.id))
            except Exception as e:
                db.session.rollback()
                flash(f"Wystąpił błąd: {e}", "danger")

    return render_template("move_booking.html", form=form, booking=booking_to_move, user=user, session=session)


# === KOMENDY CLI ===
# To jest nowa, prosta metoda tworzenia kont (zamiast flask shell)

@app.cli.command("create-accounts")
def create_accounts():
    """Tworzy konto Menedżera i 3 konta Trenerów."""
    try:
        # --- KONTO MENEDŻERA (ADMINA) ---
        admin_email = 'admin@bodylab.pl'
        admin_pass = 'admin123'
        admin_username = 'Menedżer'

        admin_user = User.query.filter_by(email=admin_email).first()
        if not admin_user:
            admin_user = User(username=admin_username, email=admin_email, role='admin')
            admin_user.set_password(admin_pass)
            db.session.add(admin_user)
            print(f"Stworzono MENEDŻERA: {admin_email}")

        # === TWOJE KONTA TRENERÓW ===
        TRENERZY_DO_STWORZENIA = [
            {"imie": "Arina Dziuba", "email": "arina@bodylab.pl", "haslo": "trener123"},
            {"imie": "Laura Iwanowska", "email": "laura@bodylab.pl", "haslo": "trener123"},
            {"imie": "Wiktoria Durtan", "email": "wiktoria@bodylab.pl", "haslo": "trener123"}
        ]

        print("\n--- Tworzenie kont trenerów ---")

        for dane in TRENERZY_DO_STWORZENIA:
            name = dane["imie"]
            email = dane["email"]
            password = dane["haslo"]

            trainer = User.query.filter_by(email=email).first()
            if not trainer:
                trainer = User(username=name, email=email, role='trainer')
                trainer.set_password(password)
                db.session.add(trainer)
                print(f"Stworzono TRENERA: {name} ({email})")
            else:
                print(f"INFO: Trener z adresem {email} już istnieje. Pomijam.")

        db.session.commit()
        print("\nGotowe! Wszystkie konta zostały utworzone.")

    except Exception as e:
        db.session.rollback()
        print(f"\n--- WYSTĄPIŁ KRYTYCZNY BŁĄD: {e} ---")


if __name__ == "__main__":
    app.run(debug=True, port=5001)