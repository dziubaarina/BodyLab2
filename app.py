from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField, IntegerField, DecimalField
from wtforms.fields import DateField, TimeField  # Importy dla daty i czasu
from wtforms.validators import DataRequired, Email, EqualTo, NumberRange, Optional
from config import Config
from functools import wraps
from datetime import date, time, datetime  # Importy Pythona dla daty i czasu
from sqlalchemy import Date, Time, exc  # Importy SQLAlchemy

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = "login"


def init_db():
    # Ta funkcja jest teraz tylko definicją, nie jest wywoływana automatycznie
    from flask_migrate import upgrade
    with app.app_context():
        upgrade()


# === MODELE BAZY DANYCH ===

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False, server_default='0')

    # --- NOWE POLA DLA PROFILU TRENERA ---
    experience_notes = db.Column(db.Text, nullable=True,
                                 default="Trener z wieloletnim doświadczeniem.")  # Notatki o doświadczeniu

    # --- NOWE RELACJE ---
    # Zajęcia prowadzone przez trenera (jako admin)
    sessions_taught = db.relationship('TrainingSession', back_populates='trainer', lazy='dynamic')

    # Rezerwacje zrobione przez użytkownika
    bookings = db.relationship('Booking', back_populates='user', lazy='dynamic')

    # Wiadomości
    messages_sent = db.relationship('Message', foreign_keys='Message.sender_id', back_populates='sender',
                                    lazy='dynamic')
    messages_received = db.relationship('Message', foreign_keys='Message.recipient_id', back_populates='recipient',
                                        lazy='dynamic')

    # Relacja do starego dzienniczka
    workouts = db.relationship('Workout', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'


# === NOWY MODEL: ZAJĘCIA (TRENINGI) ===
class TrainingSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    session_type = db.Column(db.String(20), nullable=False, default='Grupowy')  # "Grupowy" lub "Indywidualny"
    description = db.Column(db.Text, nullable=True)

    date = db.Column(db.Date, nullable=False)
    start_time = db.Column(db.Time, nullable=False)
    duration_minutes = db.Column(db.Integer, nullable=False, default=60)

    price = db.Column(db.Integer, nullable=False, default=0)
    max_participants = db.Column(db.Integer, nullable=False, default=10)

    trainer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Relacje
    trainer = db.relationship('User', back_populates='sessions_taught')
    bookings = db.relationship('Booking', back_populates='session', lazy='dynamic', cascade="all, delete-orphan")

    @property
    def current_participants(self):
        return self.bookings.count()

    @property
    def is_full(self):
        return self.bookings.count() >= self.max_participants

    @property
    def end_time(self):
        # Łączy datę i czas, aby móc dodać minuty
        full_start = datetime.combine(self.date, self.start_time)
        full_end = full_start + db.timedelta(minutes=self.duration_minutes)
        return full_end.time()

    def __repr__(self):
        return f'<Session {self.title} @ {self.date}>'


# === NOWY MODEL: REZERWACJA ===
class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_id = db.Column(db.Integer, db.ForeignKey('training_session.id'), nullable=False)

    # Relacje
    user = db.relationship('User', back_populates='bookings')
    session = db.relationship('TrainingSession', back_populates='bookings')

    # Unikalne połączenie, aby użytkownik nie zapisał się dwa razy na te same zajęcia
    __table_args__ = (db.UniqueConstraint('user_id', 'session_id', name='_user_session_uc'),)

    def __repr__(self):
        return f'<Booking {self.user.username} -> {self.session.title}>'


# === NOWY MODEL: WIADOMOŚĆ (na przyszłość) ===
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    sender = db.relationship('User', foreign_keys=[sender_id], back_populates='messages_sent')
    recipient = db.relationship('User', foreign_keys=[recipient_id], back_populates='messages_received')


# === STARE MODELE (DZIENNICZEK) ===
class Workout(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.String(10), nullable=False)
    start_time = db.Column(db.String(5), nullable=False)
    duration = db.Column(db.String(10), nullable=False)
    notes = db.Column(db.Text)
    # relacja "user" jest dodana automatycznie przez backref w modelu User


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


# Formularz starego dzienniczka
class WorkoutForm(FlaskForm):
    date = StringField("Data", validators=[DataRequired()])
    start_time = StringField("Godzina rozpoczęcia", validators=[DataRequired()])
    duration = StringField("Czas trwania", validators=[DataRequired()])
    notes = TextAreaField("Notatki")
    submit = SubmitField("Dodaj trening")


# Formularz tworzenia nowych zajęć (dla trenera)
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
    submit = SubmitField("Stwórz zajęcia")


# Formularz przenoszenia rezerwacji (dla trenera)
class MoveBookingForm(FlaskForm):
    new_session = SelectField("Wybierz nowe zajęcia", coerce=int, validators=[DataRequired()])
    submit = SubmitField("Przenieś rezerwację")


# === KONFIGURACJA LOGIN MANAGER ===

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# === DEKORATOR DLA ADMINA ===
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("Dostęp do tej strony wymaga uprawnień administratora.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)

    return decorated_function


# ... (Stare listy ćwiczeń, możesz je zostawić) ...
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
    """Zakładka Ogłoszenia – statyczna, edytowalna później przez admina"""
    # === POPRAWIONA SKŁADNIA BŁĘDU ===
    posts = [
        {
            "title": "Nowy grafik od 1 kwietnia!",
            "date": "28.03.2025",
            "content": "Wprowadzamy nowe zajęcia: CrossFit o 18:00 i Joga dla początkujących o 19:30. Zapisy już trwają!",
            "badge": "light "
        },
        {
            "title": "Bezpłatny tydzień próbny!",
            "date": "12.11.2025",
            "content": "Przyjdź od 17 do 23 listopada – trenować możesz ZA DARMO!\nTylko pokaż ten kod u recepcji: FREE7",
            "badge": "light"
        },
        {
            "title": "Zamknięte 24-26 grudnia",
            "date": "20.12.2025",
            "content": "Święta = regeneracja. Siłownia nieczynna 24-26.12.\nWracamy 27.12 z podwójną energią!",
            "badge": "light"
        },
        {
            "title": "Poranne cardio 6:30",
            "date": "13.11.2025",
            "content": "Nowe zajęcia: CARDIO START\nPon/czw 6:30-7:15\nIdealnie na początek dnia!",
            "badge": "light"
        }
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

        user = User(username=form.username.data, email=form.email.data)
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
            return redirect(url_for("dashboard"))  # Zmienione na dashboard
        flash("Błędny email lub hasło", "danger")
    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


# === STARE TRASY TRENINGOWE (DZIENNICZEK) ===
@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))

    workouts = Workout.query.filter_by(user_id=current_user.id).all()
    # To jest teraz "Mój Dzienniczek"
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
        flash("Trening dodany! Partie ciała przypisane automatycznie.", "success")
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
    workout = Workout.query.get_or_404(workout_id)
    # Sprawdzenie, czy użytkownik jest adminem LUB właścicielem treningu
    if not current_user.is_admin and workout.user_id != current_user.id:
        flash("Nie masz uprawnień do wyświetlenia tego treningu.", "danger")
        return redirect(url_for('dashboard'))

    exercises = Exercise.query.filter_by(workout_id=workout.id).all()
    return render_template("view_workout.html", workout=workout, exercises=exercises)


# === NOWE TRASY DLA SYSTEMU REZERWACJI ===

@app.route("/booking", methods=["GET"])
@login_required
def booking():
    today = date.today()

    # Pobieramy ID sesji, na które użytkownik jest już zapisany
    user_bookings = current_user.bookings.all()
    user_booked_session_ids = {booking.session_id for booking in user_bookings}

    # Pobieramy wszystkie nadchodzące zajęcia
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
    session_to_book = TrainingSession.query.get_or_404(session_id)

    # Sprawdzenie, czy użytkownik nie jest już zapisany
    existing_booking = Booking.query.filter_by(user_id=current_user.id, session_id=session_id).first()
    if existing_booking:
        flash("Jesteś już zapisany/a na te zajęcia.", "info")
        return redirect(url_for('booking'))

    # Sprawdzenie, czy są wolne miejsca
    if session_to_book.is_full:
        flash("Niestety, na te zajęcia nie ma już wolnych miejsc.", "danger")
        return redirect(url_for('booking'))

    # Sprawdzenie, czy użytkownik nie próbuje zapisać się na własne zajęcia (jeśli jest trenerem)
    if session_to_book.trainer_id == current_user.id:
        flash("Nie możesz zapisać się na własne zajęcia.", "warning")
        return redirect(url_for('booking'))

    # Tworzenie rezerwacji
    try:
        new_booking = Booking(user_id=current_user.id, session_id=session_id)
        db.session.add(new_booking)

        # W przyszłości: wyślij wiadomość w czacie
        # Na razie: wyślij wiadomość "systemową" (jeszcze nie zaimplementowane)
        # msg_content = f"Cześć! Twoja rezerwacja na zajęcia '{session_to_book.title}' w dniu {session_to_book.date} o {session_to_book.start_time} została potwierdzona."
        # confirmation_msg = Message(sender_id=session_to_book.trainer_id, recipient_id=current_user.id, content=msg_content)
        # db.session.add(confirmation_msg)

        db.session.commit()
        flash(f"Pomyślnie zapisano na zajęcia: {session_to_book.title}!", "success")
    except exc.IntegrityError:  # Błąd, jeśli rezerwacja już istnieje (UniqueConstraint)
        db.session.rollback()
        flash("Jesteś już zapisany/a na te zajęcia.", "info")
    except Exception as e:
        db.session.rollback()
        flash(f"Wystąpił błąd podczas rezerwacji: {e}", "danger")

    return redirect(url_for('booking'))


@app.route("/trainer_profile/<int:trainer_id>")
@login_required
def trainer_profile(trainer_id):
    trainer = User.query.get_or_404(trainer_id)
    if not trainer.is_admin:  # Tylko admini (trenerzy) mają publiczne profile
        flash("Ten użytkownik nie jest trenerem.", "danger")
        return redirect(url_for('booking'))

    # W przyszłości dodamy tu więcej informacji
    return render_template("trainer_profile.html", trainer=trainer)


# === TRASY ADMINISTRATORA / TRENERA ===
@app.route("/admin")
@login_required
@admin_required
def admin_dashboard():
    all_users = User.query.all()
    # Pobieramy zajęcia stworzone przez zalogowanego trenera
    my_sessions = TrainingSession.query.filter_by(trainer_id=current_user.id).order_by(
        TrainingSession.date.desc(), TrainingSession.start_time.desc()).all()

    return render_template("admin.html", users=all_users, my_sessions=my_sessions)


@app.route("/create_session", methods=["GET", "POST"])
@login_required
@admin_required
def create_session():
    form = SessionForm()
    if form.validate_on_submit():
        try:
            new_session = TrainingSession(
                title=form.title.data,
                session_type=form.session_type.data,
                description=form.description.data,
                date=form.date.data,
                start_time=form.start_time.data,
                duration_minutes=form.duration_minutes.data,
                price=form.price.data,
                max_participants=form.max_participants.data,
                trainer_id=current_user.id  # Trenerem jest zalogowany admin
            )
            db.session.add(new_session)
            db.session.commit()
            flash(f"Pomyślnie utworzono nowe zajęcia: {new_session.title}", "success")
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f"Wystąpił błąd podczas tworzenia zajęć: {e}", "danger")

    # Ustawienie domyślnej daty na dzisiaj
    if not form.date.data:
        form.date.data = date.today()

    return render_template("create_session.html", form=form, title="Stwórz Nowe Zajęcia")


@app.route("/manage_session/<int:session_id>")
@login_required
@admin_required
def manage_session(session_id):
    session = TrainingSession.query.get_or_404(session_id)
    # Upewnij się, że trener może zarządzać tylko swoimi zajęciami
    if session.trainer_id != current_user.id:
        flash("Nie masz uprawnień do zarządzania tymi zajęciami.", "danger")
        return redirect(url_for('admin_dashboard'))

    return render_template("manage_session.html", session=session)


@app.route("/cancel_booking/<int:booking_id>", methods=["POST"])
@login_required
@admin_required
def cancel_booking(booking_id):
    booking_to_cancel = Booking.query.get_or_404(booking_id)
    session_id = booking_to_cancel.session.id

    # Upewnij się, że trener zarządza swoimi zajęciami
    if booking_to_cancel.session.trainer_id != current_user.id:
        flash("Nie masz uprawnień do anulowania tej rezerwacji.", "danger")
        return redirect(url_for('admin_dashboard'))

    try:
        db.session.delete(booking_to_cancel)
        db.session.commit()
        flash(f"Pomyślnie anulowano rezerwację dla {booking_to_cancel.user.username}.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Wystąpił błąd podczas anulowania: {e}", "danger")

    return redirect(url_for('manage_session', session_id=session_id))


@app.route("/move_booking/<int:booking_id>", methods=["GET", "POST"])
@login_required
@admin_required
def move_booking(booking_id):
    booking_to_move = Booking.query.get_or_404(booking_id)

    # Upewnij się, że trener zarządza swoimi zajęciami
    if booking_to_move.session.trainer_id != current_user.id:
        flash("Nie masz uprawnień do przenoszenia tej rezerwacji.", "danger")
        return redirect(url_for('admin_dashboard'))

    form = MoveBookingForm()

    # Pobierz listę wszystkich INNYCH, nadchodzących zajęć prowadzonych przez tego trenera, które nie są pełne
    today = date.today()
    available_sessions = TrainingSession.query.filter(
        TrainingSession.trainer_id == current_user.id,
        TrainingSession.date >= today,
        TrainingSession.id != booking_to_move.session_id  # Nie można przenieść na te same zajęcia
    ).order_by(TrainingSession.date, TrainingSession.start_time).all()

    # Filtrujemy listę, aby pokazać tylko te, które nie są pełne
    # (Trudno to zrobić w zapytaniu SQL, łatwiej w Pythonie)
    form.new_session.choices = [
        (s.id,
         f"{s.date} o {s.start_time.strftime('%H:%M')} - {s.title} ({s.current_participants}/{s.max_participants})")
        for s in available_sessions if not s.is_full
    ]

    if form.validate_on_submit():
        new_session_id = form.new_session.data
        new_session = TrainingSession.query.get(new_session_id)

        # Sprawdzenie, czy użytkownik nie jest już zapisany na nowe zajęcia
        is_already_booked = Booking.query.filter_by(user_id=booking_to_move.user_id, session_id=new_session_id).first()
        if is_already_booked:
            flash(f"{booking_to_move.user.username} jest już zapisany na wybrane zajęcia.", "warning")
            return redirect(url_for('manage_session', session_id=booking_to_move.session_id))

        try:
            # Zmień ID sesji w istniejącej rezerwacji
            booking_to_move.session_id = new_session_id
            db.session.commit()
            flash(f"Pomyślnie przeniesiono {booking_to_move.user.username} na zajęcia {new_session.title}.", "success")
            return redirect(url_for('manage_session', session_id=new_session_id))
        except Exception as e:
            db.session.rollback()
            flash(f"Wystąpił błąd podczas przenoszenia rezerwacji: {e}", "danger")

    return render_template("move_booking.html",
                           form=form,
                           booking=booking_to_move,
                           title="Przenieś Rezerwację")


# === URUCHOMIENIE APLIKACJI ===
if __name__ == "__main__":
    # Usunąłem stąd `init_db()`, aby aplikacja nie próbowała
    # migrować bazy danych przy każdym uruchomieniu.
    # Uruchom `flask db upgrade` RĘCZNIE w terminalu.
    app.run(debug=True, port=5001)  # Używam portu 5001, aby uniknąć konfliktów