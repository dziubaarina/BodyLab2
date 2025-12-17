from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField, IntegerField, HiddenField, \
    BooleanField
from wtforms.fields import DateField, TimeField
from wtforms.validators import DataRequired, Email, EqualTo, NumberRange, InputRequired
from config import Config
from functools import wraps
from datetime import date, time, datetime, timedelta
import uuid
from sqlalchemy import Date, Time, or_
import sys
import click

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
    role = db.Column(db.String(20), nullable=False, default='user')
    experience_notes = db.Column(db.Text, nullable=True)

    sessions_taught = db.relationship('TrainingSession', back_populates='trainer', lazy='dynamic')
    bookings = db.relationship('Booking', back_populates='user', lazy='dynamic')
    messages_sent = db.relationship('Message', foreign_keys='Message.sender_id', back_populates='sender',
                                    lazy='dynamic')
    messages_received = db.relationship('Message', foreign_keys='Message.recipient_id', back_populates='recipient',
                                        lazy='dynamic')

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
    recurrence_group_id = db.Column(db.String(36), nullable=True, index=True)

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
    trainer = SelectField("Prowadzący Trener", coerce=int, validators=[InputRequired()])
    is_recurring = BooleanField("Zajęcia cykliczne (co tydzień)")
    recurrence_weeks = IntegerField("Powtórz przez (liczba tygodni)", default=4,
                                    validators=[NumberRange(min=1, max=52)])
    submit = SubmitField("Zapisz zajęcia")

    def __init__(self, *args, **kwargs):
        super(SessionForm, self).__init__(*args, **kwargs)
        self.trainer.choices = [(u.id, u.username) for u in
                                User.query.filter(or_(User.role == 'trainer', User.role == 'admin')).all()]


class MoveBookingForm(FlaskForm):
    new_session = SelectField("Wybierz nowe zajęcia", coerce=int, validators=[DataRequired()])
    submit = SubmitField("Przenieś rezerwację")

    def __init__(self, original_session_id=None, *args, **kwargs):
        super(MoveBookingForm, self).__init__(*args, **kwargs)
        today = date.today()
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
    return db.session.get(User, int(user_id))


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("Dostęp do tej strony wymaga uprawnień Menedżera.", "danger")
            return redirect(url_for('index'))
        return f(*args, **kwargs)

    return decorated_function


def trainer_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or (not current_user.is_admin and not current_user.is_trainer):
            flash("Dostęp do tej strony wymaga uprawnień Trenera.", "danger")
            return redirect(url_for('index'))
        return f(*args, **kwargs)

    return decorated_function


# === LISTY ĆWICZEŃ ===
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


# === TRASY UŻYTKOWNIKA ===

@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    if current_user.is_trainer:
        return redirect(url_for('trainer_dashboard'))

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

        exercise_names = request.form.getlist('exercise_name')
        exercise_sets = request.form.getlist('exercise_sets')
        exercise_reps = request.form.getlist('exercise_reps')

        for i in range(len(exercise_names)):
            name = exercise_names[i].strip()
            if name:
                body_part = EXERCISE_TO_BODY_PART.get(name, "Inne")
                exercise = Exercise(
                    workout_id=workout.id,
                    body_part=body_part,
                    name=name,
                    sets=int(exercise_sets[i]),
                    reps=int(exercise_reps[i])
                )
                db.session.add(exercise)

        db.session.commit()
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
@app.route("/delete_workout/<int:workout_id>", methods=["POST"])
@login_required
def delete_workout(workout_id):
    workout = db.session.get(Workout, workout_id)

    if not workout:
        flash("Nie znaleziono treningu.", "danger")
        return redirect(url_for('workout_history'))

    # Sprawdź uprawnienia - tylko właściciel lub admin może usunąć
    if not current_user.is_admin and workout.user_id != current_user.id:
        flash("Nie masz uprawnień do usunięcia tego treningu.", "danger")
        return redirect(url_for('workout_history'))

    try:
        workout_date = workout.date
        # Usuń powiązane ćwiczenia (cascade powinno to zrobić automatycznie, ale dla pewności)
        Exercise.query.filter_by(workout_id=workout.id).delete()
        db.session.delete(workout)
        db.session.commit()
        flash(f"Usunięto trening z dnia {workout_date}.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Wystąpił błąd podczas usuwania: {e}", "danger")

    return redirect(url_for('workout_history'))


@app.route("/delete_all_workouts", methods=["POST"])
@login_required
def delete_all_workouts():
    """Usuwa wszystkie treningi użytkownika"""
    try:
        # Usuń wszystkie ćwiczenia powiązane z treningami użytkownika
        workout_ids = [w.id for w in Workout.query.filter_by(user_id=current_user.id).all()]
        Exercise.query.filter(Exercise.workout_id.in_(workout_ids)).delete(synchronize_session=False)

        # Usuń wszystkie treningi użytkownika
        count = Workout.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()

        flash(f"Usunięto {count} treningów z historii.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Wystąpił błąd podczas usuwania: {e}", "danger")

    return redirect(url_for('workout_history'))
@login_required
def view_workout(workout_id):
    workout = db.session.get(Workout, workout_id)
    if not workout:
        flash("Nie znaleziono takiego treningu.", "danger")
        return redirect(url_for('workout_history'))

    if not (current_user.is_admin or current_user.is_trainer) and workout.user_id != current_user.id:
        flash("Nie masz uprawnień do wyświetlenia tego treningu.", "danger")
        return redirect(url_for('dashboard'))

    exercises = Exercise.query.filter_by(workout_id=workout.id).all()
    return render_template("view_workout.html", workout=workout, exercises=exercises)


# === NOWE TRASY SYSTEMU REZERWACJI (Z GRUPOWANIEM CYKLI) ===

@app.route("/booking", methods=["GET"])
@login_required
def booking():
    today = date.today()
    user_booked_session_ids = {booking.session_id for booking in current_user.bookings.all()}

    # Pobierz WSZYSTKIE przyszłe sesje
    all_sessions = TrainingSession.query.filter(
        TrainingSession.date >= today
    ).order_by(TrainingSession.date, TrainingSession.start_time).all()

    # Logika grupowania:
    # Jeśli sesja ma recurrence_group_id, pokaż ją tylko RAZ (pierwsze wystąpienie)
    # ale przekaż listę wszystkich wystąpień w tej grupie.

    grouped_items_grupowe = []
    grouped_items_indywidualne = []

    seen_groups = set()  # Zestaw ID grup, które już przetworzyliśmy

    for session in all_sessions:
        item_data = {'type': 'single', 'session': session}

        # Jeśli to sesja cykliczna
        if session.recurrence_group_id:
            if session.recurrence_group_id in seen_groups:
                continue  # Już dodaliśmy "reprezentanta" tej grupy, pomijamy

            seen_groups.add(session.recurrence_group_id)
            item_data['type'] = 'recurring_group'

            # Znajdź wszystkie sesje z tej grupy (przyszłe)
            group_sessions = [s for s in all_sessions if s.recurrence_group_id == session.recurrence_group_id]
            item_data['group_sessions'] = group_sessions

        # Podział na typy (Grupowy/Indywidualny)
        if session.session_type == 'Grupowy':
            grouped_items_grupowe.append(item_data)
        else:
            grouped_items_indywidualne.append(item_data)

    return render_template("booking.html",
                           items_grupowe=grouped_items_grupowe,
                           items_indywidualne=grouped_items_indywidualne,
                           user_booked_session_ids=user_booked_session_ids,
                           today=today)


@app.route("/book_session", methods=["POST"])
@login_required
def book_session():
    session_id = request.form.get('session_id')
    book_recurring = request.form.get('book_recurring')  # 'yes' jeśli zapis na grupę

    session_to_book = db.session.get(TrainingSession, session_id)

    if not session_to_book:
        flash("Nie znaleziono takich zajęć.", "danger")
        return redirect(url_for('booking'))

    if session_to_book.trainer_id == current_user.id:
        flash("Nie możesz zapisać się na własne zajęcia.", "warning")
        return redirect(url_for('booking'))

    # --- ZAPIS NA CAŁY CYKL (GRUPĘ) ---
    if book_recurring == 'yes' and session_to_book.recurrence_group_id:
        # Znajdź wszystkie PRZYSZŁE zajęcia z tej grupy
        future_sessions = TrainingSession.query.filter(
            TrainingSession.recurrence_group_id == session_to_book.recurrence_group_id,
            TrainingSession.date >= date.today()
        ).all()

        count_success = 0

        for session in future_sessions:
            # Sprawdź, czy już zapisany
            existing = Booking.query.filter_by(user_id=current_user.id, session_id=session.id).first()
            if existing:
                continue  # Już zapisany, pomijamy

            # Sprawdź, czy pełne
            if session.is_full:
                continue  # Pełne, pomijamy

            # Zapisz
            new_booking = Booking(user_id=current_user.id, session_id=session.id)
            db.session.add(new_booking)
            count_success += 1

        try:
            db.session.commit()
            flash(f"Zapisano na {count_success} zajęć z cyklu.", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Wystąpił błąd podczas zapisu grupowego: {e}", "danger")

    else:
        # --- ZAPIS POJEDYNCZY ---
        existing_booking = Booking.query.filter_by(user_id=current_user.id, session_id=session_id).first()
        if existing_booking:
            flash("Jesteś już zapisany/a na te zajęcia.", "info")
            return redirect(url_for('booking'))

        if session_to_book.is_full:
            flash("Niestety, na te zajęcia nie ma już wolnych miejsc.", "danger")
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


@app.route("/unbook_session", methods=["POST"])
@login_required
def unbook_session():
    session_id = request.form.get('session_id')
    booking = Booking.query.filter_by(user_id=current_user.id, session_id=session_id).first()

    if booking:
        try:
            if booking.session.date < date.today():
                flash("Nie możesz wypisać się z zajęć, które już się odbyły.", "warning")
                return redirect(url_for('booking'))

            db.session.delete(booking)
            db.session.commit()
            flash("Pomyślnie wypisano z zajęć.", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Wystąpił błąd: {e}", "danger")
    else:
        flash("Nie znaleziono rezerwacji.", "info")

    return redirect(url_for('booking'))


@app.route("/trainer_profile/<int:trainer_id>")
@login_required
def trainer_profile(trainer_id):
    trainer = db.session.get(User, trainer_id)
    if not trainer or (not trainer.is_admin and not trainer.is_trainer):
        flash("Ten użytkownik nie jest trenerem.", "danger")
        return redirect(url_for('booking'))
    return render_template("trainer_profile.html", trainer=trainer)


# === TRASY MENEDŻERA I TRENERA ===

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
    user_to_edit = db.session.get(User, user_id)
    new_role = request.form.get('role')
    if user_to_edit and new_role in ['user', 'trainer', 'admin']:
        if user_to_edit.id == current_user.id and new_role != 'admin':
            flash("Nie możesz odebrać sobie uprawnień administratora.", "danger")
        else:
            user_to_edit.role = new_role
            db.session.commit()
            flash(f"Zaktualizowano rolę: {new_role}", "success")
    else:
        flash("Wystąpił błąd.", "danger")
    return redirect(url_for('admin_dashboard'))


@app.route("/trainer")
@login_required
@trainer_required
def trainer_dashboard():
    query = TrainingSession.query
    if not current_user.is_admin:
        query = query.filter_by(trainer_id=current_user.id)
    my_sessions = query.order_by(TrainingSession.date.desc()).all()
    return render_template("trainer_dashboard.html", my_sessions=my_sessions)


@app.route("/create_session", methods=["GET", "POST"])
@login_required
@trainer_required
def create_session():
    form = SessionForm()
    if not current_user.is_admin:
        form.trainer.data = current_user.id

    if form.validate_on_submit():
        try:
            trainer_id_to_assign = form.trainer.data

            if form.is_recurring.data:
                num_weeks = form.recurrence_weeks.data
                start_date = form.date.data
                group_id = str(uuid.uuid4())

                for i in range(num_weeks):
                    session_date = start_date + timedelta(weeks=i)
                    new_session = TrainingSession(
                        title=form.title.data,
                        session_type=form.session_type.data,
                        description=form.description.data,
                        date=session_date,
                        start_time=form.start_time.data,
                        duration_minutes=form.duration_minutes.data,
                        price=form.price.data,
                        max_participants=form.max_participants.data,
                        trainer_id=trainer_id_to_assign,
                        recurrence_group_id=group_id
                    )
                    db.session.add(new_session)
                flash(f"Utworzono {num_weeks} cyklicznych zajęć.", "success")
            else:
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
                flash("Utworzono nowe zajęcia.", "success")

            db.session.commit()
            return redirect(url_for('trainer_dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f"Wystąpił błąd: {e}", "danger")

    if not form.date.data:
        form.date.data = date.today()
    return render_template("create_session.html", form=form, title="Stwórz Nowe Zajęcia")


@app.route("/manage_session/<int:session_id>")
@login_required
@trainer_required
def manage_session(session_id):
    session = db.session.get(TrainingSession, session_id)
    if not session:
        flash("Nie znaleziono zajęć.", "danger")
        return redirect(url_for('trainer_dashboard'))
    if not current_user.is_admin and session.trainer_id != current_user.id:
        flash("Brak uprawnień.", "danger")
        return redirect(url_for('trainer_dashboard'))
    return render_template("manage_session.html", session=session)


@app.route("/cancel_booking/<int:booking_id>", methods=["POST"])
@login_required
@trainer_required
def cancel_booking(booking_id):
    booking = db.session.get(Booking, booking_id)
    if not booking:
        return redirect(url_for('trainer_dashboard'))

    session_id = booking.session.id
    if not current_user.is_admin and booking.session.trainer_id != current_user.id:
        return redirect(url_for('manage_session', session_id=session_id))

    db.session.delete(booking)
    db.session.commit()
    flash("Anulowano rezerwację.", "success")
    return redirect(url_for('manage_session', session_id=session_id))


@app.route("/move_booking/<int:booking_id>", methods=["GET", "POST"])
@login_required
@trainer_required
def move_booking(booking_id):
    booking_to_move = db.session.get(Booking, booking_id)
    if not booking_to_move:
        return redirect(url_for('trainer_dashboard'))

    session = booking_to_move.session
    user = booking_to_move.user

    if not current_user.is_admin and session.trainer_id != current_user.id:
        return redirect(url_for('trainer_dashboard'))

    form = MoveBookingForm(original_session_id=session.id)

    if form.validate_on_submit():
        new_session = db.session.get(TrainingSession, form.new_session.data)
        if new_session and not new_session.is_full:
            booking_to_move.session_id = new_session.id
            db.session.commit()
            flash("Przeniesiono rezerwację.", "success")
            return redirect(url_for('manage_session', session_id=session.id))
        else:
            flash("Błąd przenoszenia.", "danger")

    return render_template("move_booking.html", form=form, booking=booking_to_move, user=user, session=session)


@app.route("/delete_session/<int:session_id>", methods=["POST"])
@login_required
@trainer_required
def delete_session(session_id):
    session = db.session.get(TrainingSession, session_id)

    if not session:
        flash("Nie znaleziono zajęć.", "danger")
        return redirect(url_for('trainer_dashboard'))

    # Sprawdź uprawnienia
    if not current_user.is_admin and session.trainer_id != current_user.id:
        flash("Brak uprawnień do usunięcia tych zajęć.", "danger")
        return redirect(url_for('trainer_dashboard'))

    # Sprawdź czy są rezerwacje
    if session.bookings.count() > 0:
        flash("Nie można usunąć zajęć z aktywnymi rezerwacjami. Najpierw anuluj wszystkie rezerwacje.", "warning")
        return redirect(url_for('manage_session', session_id=session_id))

    try:
        session_title = session.title
        session_date = session.date.strftime('%Y-%m-%d')
        db.session.delete(session)
        db.session.commit()
        flash(f"Usunięto zajęcia: {session_title} ({session_date})", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Wystąpił błąd podczas usuwania: {e}", "danger")

    return redirect(url_for('trainer_dashboard'))


@app.route("/delete_recurring_group/<group_id>", methods=["POST"])
@login_required
@trainer_required
def delete_recurring_group(group_id):
    """Usuwa wszystkie przyszłe zajęcia z grupy cyklicznej"""
    sessions = TrainingSession.query.filter(
        TrainingSession.recurrence_group_id == group_id,
        TrainingSession.date >= date.today()
    ).all()

    if not sessions:
        flash("Nie znaleziono zajęć cyklicznych.", "danger")
        return redirect(url_for('trainer_dashboard'))

    # Sprawdź uprawnienia (sprawdzamy pierwszą sesję)
    if not current_user.is_admin and sessions[0].trainer_id != current_user.id:
        flash("Brak uprawnień.", "danger")
        return redirect(url_for('trainer_dashboard'))

    # Sprawdź czy któraś sesja ma rezerwacje
    sessions_with_bookings = [s for s in sessions if s.bookings.count() > 0]
    if sessions_with_bookings:
        dates_str = ", ".join([s.date.strftime('%Y-%m-%d') for s in sessions_with_bookings[:3]])
        flash(
            f"Nie można usunąć {len(sessions_with_bookings)} zajęć z grupy, które mają aktywne rezerwacje (np. {dates_str}). Najpierw anuluj rezerwacje.",
            "warning")
        return redirect(url_for('trainer_dashboard'))

    try:
        count = len(sessions)
        title = sessions[0].title
        for session in sessions:
            db.session.delete(session)
        db.session.commit()
        flash(f"Usunięto {count} zajęć z cyklu '{title}'.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Wystąpił błąd: {e}", "danger")

    return redirect(url_for('trainer_dashboard'))

# === CLI ===
@app.cli.command("create-accounts")
def create_accounts():
    try:
        admin = User.query.filter_by(email='admin@bodylab.pl').first()
        if not admin:
            admin = User(username='Menedżer', email='admin@bodylab.pl', role='admin')
            admin.set_password('admin123')
            db.session.add(admin)
            print("Stworzono admina.")

        trainers = [
            {"imie": "Arina Dziuba", "email": "arina@bodylab.pl"},
            {"imie": "Laura Iwanowska", "email": "laura@bodylab.pl"},
            {"imie": "Wiktoria Durtan", "email": "wiktoria@bodylab.pl"}
        ]
        for t in trainers:
            if not User.query.filter_by(email=t['email']).first():
                tr = User(username=t['imie'], email=t['email'], role='trainer')
                tr.set_password('trener123')
                db.session.add(tr)
                print(f"Stworzono trenera: {t['imie']}")

        db.session.commit()
        print("Gotowe.")
    except Exception as e:
        print(e)


if __name__ == "__main__":
    app.run(debug=True, port=5001)