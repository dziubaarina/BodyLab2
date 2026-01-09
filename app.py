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
import os

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Zaloguj się, aby uzyskać dostęp."
login_manager.login_message_category = "info"


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
    def is_admin(self): return self.role == 'admin'

    @property
    def is_trainer(self): return self.role == 'trainer'

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
    def current_participants(self): return self.bookings.count()

    @property
    def is_full(self): return self.bookings.count() >= self.max_participants


class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_id = db.Column(db.Integer, db.ForeignKey('training_session.id'), nullable=False)
    is_recurring_booking = db.Column(db.Boolean, default=False)
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
    user = db.relationship('User', backref=db.backref('workouts_ref', lazy=True))


class Exercise(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    workout_id = db.Column(db.Integer, db.ForeignKey('workout.id'), nullable=False)
    body_part = db.Column(db.String(50), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    sets = db.Column(db.Integer, nullable=False)
    reps = db.Column(db.Integer, nullable=False)
    workout = db.relationship('Workout', backref=db.backref('exercises', lazy=True, cascade="all, delete-orphan"))


# === FORMULARZE ===

class RegisterForm(FlaskForm):
    username = StringField("Nazwa użytkownika", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Hasło",
                             validators=[DataRequired(), EqualTo('password2', message='Hasła muszą być identyczne')])
    password2 = PasswordField("Powtórz hasło", validators=[DataRequired()])
    submit = SubmitField("Zarejestruj się")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Hasło", validators=[DataRequired()])
    submit = SubmitField("Zaloguj się")


class WorkoutForm(FlaskForm):
    date = StringField("Data", validators=[DataRequired()])
    start_time = StringField("Godzina rozpoczęcia", validators=[DataRequired()])
    duration = StringField("Czas trwania (min)", validators=[DataRequired()])
    notes = TextAreaField("Notatki")
    submit = SubmitField("Zapisz trening")


class SessionForm(FlaskForm):
    title = StringField("Tytuł zajęć", validators=[DataRequired()])
    session_type = SelectField("Typ zajęć", choices=[('Grupowy', 'Grupowy'), ('Indywidualny', 'Indywidualny')],
                               validators=[DataRequired()])
    description = TextAreaField("Opis zajęć")
    date = DateField("Data", validators=[DataRequired()], format='%Y-%m-%d')
    start_time = TimeField("Godzina rozpoczęcia", validators=[DataRequired()], format='%H:%M')
    duration_minutes = IntegerField("Czas trwania (min)", validators=[DataRequired(), NumberRange(min=30, max=240)],
                                    default=60)
    price = IntegerField("Cena (zł)", validators=[DataRequired(), NumberRange(min=0)], default=0)
    max_participants = IntegerField("Limit miejsc", validators=[DataRequired(), NumberRange(min=1)], default=10)
    trainer = SelectField("Prowadzący Trener", coerce=int, validators=[InputRequired()])
    is_recurring = BooleanField("Zajęcia cykliczne (co tydzień)")
    recurrence_weeks = IntegerField("Liczba tygodni", default=4, validators=[NumberRange(min=1, max=52)])
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
        self.new_session.choices = [(s.id, f"{s.title} ({s.date})") for s in
                                    TrainingSession.query.filter(TrainingSession.date >= today,
                                                                 TrainingSession.id != original_session_id).all() if
                                    not s.is_full]


# === DEKORATORY I FUNKCJE POMOCNICZE ===

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("Dostęp tylko dla Menedżera.", "danger")
            return redirect(url_for('index'))
        return f(*args, **kwargs)

    return decorated_function


def trainer_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or (not current_user.is_admin and not current_user.is_trainer):
            flash("Dostęp tylko dla Trenera.", "danger")
            return redirect(url_for('index'))
        return f(*args, **kwargs)

    return decorated_function


EXERCISE_SUGGESTIONS = ["Przysiady ze sztangą", "Przysiady bułgarskie", "Martwy ciąg", "Wiosłowanie", "Podciąganie",
                        "Wyciskanie leżąc", "Plank", "Burpees"]
EXERCISE_TO_BODY_PART = {"Przysiady ze sztangą": "Nogi", "Martwy ciąg": "Plecy", "Wyciskanie leżąc": "Klatka",
                         "Plank": "Brzuch"}


# === TRASY PUBLICZNE ===

@app.route("/")
def index(): return render_template("index.html")


@app.route("/cennik")
def pricing(): return render_template("pricing.html")


@app.route("/infrastruktura")
def infrastructure(): return render_template("infrastructure.html")


@app.route("/faq")
def faq(): return render_template("faq.html")


@app.route("/announcements")
def announcements():
    posts = [{"title": "Nowy grafik!", "date": "28.03.2025", "content": "Zapraszamy na nowe zajęcia."}]
    return render_template("announcements.html", posts=posts)


# === TRASY LOGOWANIA ===

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash("Ten email jest już zajęty.", "danger")
            return redirect(url_for("register"))
        user = User(username=form.username.data, email=form.email.data, role='user')
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash("Zarejestrowano pomyślnie!", "success")
        return redirect(url_for("login"))
    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash(f"Witaj, {user.username}!", "success")
            if user.is_admin: return redirect(url_for('admin_dashboard'))
            if user.is_trainer: return redirect(url_for('trainer_dashboard'))
            return redirect(url_for('dashboard'))
        flash("Błędny email lub hasło.", "danger")
    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


# === TRASY UŻYTKOWNIKA ===

@app.route("/dashboard")
@login_required
def dashboard():
    workouts = Workout.query.filter_by(user_id=current_user.id).all()
    return render_template("dashboard.html", user=current_user, workouts=workouts)


@app.route("/add_workout", methods=["GET", "POST"])
@login_required
def add_workout():
    form = WorkoutForm()
    if form.validate_on_submit():
        w = Workout(user_id=current_user.id, date=form.date.data, start_time=form.start_time.data,
                    duration=form.duration.data, notes=form.notes.data)
        db.session.add(w)
        db.session.commit()

        ex_names = request.form.getlist('exercise_name')
        ex_sets = request.form.getlist('exercise_sets')
        ex_reps = request.form.getlist('exercise_reps')
        for i in range(len(ex_names)):
            name = ex_names[i].strip()
            if name:
                ex = Exercise(workout_id=w.id, body_part=EXERCISE_TO_BODY_PART.get(name, "Inne"), name=name,
                              sets=int(ex_sets[i]), reps=int(ex_reps[i]))
                db.session.add(ex)
        db.session.commit()
        flash("Trening dodany!", "success")
        return redirect(url_for("dashboard"))
    return render_template("add_workout.html", form=form, exercise_suggestions=EXERCISE_SUGGESTIONS)


@app.route("/workout_history")
@login_required
def workout_history():
    workouts = Workout.query.filter_by(user_id=current_user.id).order_by(Workout.id.desc()).all()
    return render_template("workout_history.html", workouts=workouts)


@app.route("/view_workout/<int:workout_id>")
@login_required
def view_workout(workout_id):
    workout = db.session.get(Workout, workout_id)
    if not workout or (workout.user_id != current_user.id and not current_user.is_admin):
        flash("Brak dostępu.", "danger")
        return redirect(url_for('workout_history'))
    exercises = Exercise.query.filter_by(workout_id=workout.id).all()
    return render_template("view_workout.html", workout=workout, exercises=exercises)


@app.route("/delete_workout/<int:workout_id>", methods=["POST"])
@login_required
def delete_workout(workout_id):
    workout = db.session.get(Workout, workout_id)
    if workout and (workout.user_id == current_user.id or current_user.is_admin):
        db.session.delete(workout)
        db.session.commit()
        flash("Usunięto.", "success")
    return redirect(url_for('workout_history'))


@app.route("/delete_all_workouts", methods=["POST"])
@login_required
def delete_all_workouts():
    Workout.query.filter_by(user_id=current_user.id).delete()
    db.session.commit()
    flash("Historia wyczyszczona.", "success")
    return redirect(url_for('workout_history'))


# === REZERWACJE ===

@app.route("/booking")
@login_required
def booking():
    today = date.today()
    # Pobierz wszystkie rezerwacje użytkownika
    user_bookings = Booking.query.filter_by(user_id=current_user.id).all()
    user_booked_ids = {b.session_id for b in user_bookings}

    all_sessions = TrainingSession.query.filter(TrainingSession.date >= today).order_by(TrainingSession.date).all()

    grouped_grupowe, grouped_indywidualne, seen_groups = [], [], set()

    for s in all_sessions:
        item = {'type': 'single', 'session': s, 'user_booked_count': 0, 'total_in_group': 0}

        if s.recurrence_group_id:
            if s.recurrence_group_id in seen_groups:
                continue
            seen_groups.add(s.recurrence_group_id)

            # Pobierz wszystkie sesje z tego cyklu
            group_sessions = [gs for gs in all_sessions if gs.recurrence_group_id == s.recurrence_group_id]
            group_session_ids = [gs.id for gs in group_sessions]

            # Policz ile z nich użytkownik zarezerwował
            user_booked_in_group = sum(1 for gs_id in group_session_ids if gs_id in user_booked_ids)

            item = {
                'type': 'recurring_group',
                'session': s,
                'group_sessions': group_sessions,
                'user_booked_count': user_booked_in_group,
                'total_in_group': len(group_sessions)
            }

        if s.session_type == 'Grupowy':
            grouped_grupowe.append(item)
        else:
            grouped_indywidualne.append(item)

    return render_template("booking.html",
                           items_grupowe=grouped_grupowe,
                           items_indywidualne=grouped_indywidualne,
                           user_booked_session_ids=user_booked_ids,
                           today=today)


@app.route("/book_session", methods=["POST"])
@login_required
def book_session():
    sid = int(request.form.get('session_id'))  # POPRAWKA: Konwersja na int
    recurring = request.form.get('book_recurring')
    s_to_book = db.session.get(TrainingSession, sid)

    if not s_to_book:
        flash("Nie znaleziono zajęć.", "danger")
        return redirect(url_for('booking'))

    if recurring == 'yes' and s_to_book.recurrence_group_id:
        future_s = TrainingSession.query.filter(
            TrainingSession.recurrence_group_id == s_to_book.recurrence_group_id,
            TrainingSession.date >= date.today()
        ).all()
        for s in future_s:
            if not Booking.query.filter_by(user_id=current_user.id, session_id=s.id).first() and not s.is_full:
                db.session.add(Booking(user_id=current_user.id, session_id=s.id, is_recurring_booking=True))
    else:
        if not Booking.query.filter_by(user_id=current_user.id, session_id=sid).first() and not s_to_book.is_full:
            db.session.add(Booking(user_id=current_user.id, session_id=sid, is_recurring_booking=False))

    db.session.commit()
    flash("Zapisano!", "success")
    return redirect(url_for('booking'))


@app.route("/unbook_session", methods=["POST"])
@login_required
def unbook_session():
    sid = int(request.form.get('session_id'))  # POPRAWKA: Konwersja na int
    b = Booking.query.filter_by(user_id=current_user.id, session_id=sid).first()
    if b:
        db.session.delete(b)
        db.session.commit()
        flash("Wypisano.", "success")
    return redirect(url_for('booking'))


# === PANELI ZARZĄDZANIA ===

@app.route("/admin")
@login_required
@admin_required
def admin_dashboard():
    return render_template("admin.html", users=User.query.all())


@app.route("/admin/edit_user/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def admin_edit_user(user_id):
    u = db.session.get(User, user_id)
    u.role = request.form.get('role')
    db.session.commit()
    flash("Rola zmieniona.", "success")
    return redirect(url_for('admin_dashboard'))


@app.route("/trainer")
@login_required
@trainer_required
def trainer_dashboard():
    q = TrainingSession.query
    if not current_user.is_admin: q = q.filter_by(trainer_id=current_user.id)
    return render_template("trainer_dashboard.html", my_sessions=q.all())


@app.route("/create_session", methods=["GET", "POST"])
@login_required
@trainer_required
def create_session():
    form = SessionForm()

    # POPRAWKA: Dla nie-adminów ustaw tylko ich samych jako wybór
    if not current_user.is_admin:
        form.trainer.choices = [(current_user.id, current_user.username)]
        form.trainer.data = current_user.id

    if form.validate_on_submit():
        # POPRAWKA: Dla nie-adminów wymuś current_user jako trenera
        trainer_id = form.trainer.data if current_user.is_admin else current_user.id

        gid = str(uuid.uuid4()) if form.is_recurring.data else None
        weeks = form.recurrence_weeks.data if form.is_recurring.data else 1

        for i in range(weeks):
            db.session.add(TrainingSession(
                title=form.title.data,
                session_type=form.session_type.data,
                description=form.description.data,
                date=form.date.data + timedelta(weeks=i),
                start_time=form.start_time.data,
                duration_minutes=form.duration_minutes.data,
                price=form.price.data,
                max_participants=form.max_participants.data,
                trainer_id=trainer_id,  # POPRAWKA: Używaj trainer_id
                recurrence_group_id=gid
            ))

        db.session.commit()
        flash("Utworzono zajęcia!", "success")
        return redirect(url_for('trainer_dashboard'))

    return render_template("create_session.html", form=form, title="Stwórz Nowe Zajęcia")


@app.route("/manage_session/<int:session_id>")
@login_required
@trainer_required
def manage_session(session_id):
    s = db.session.get(TrainingSession, session_id)
    if not s:
        flash("Nie znaleziono zajęć.", "danger")
        return redirect(url_for('trainer_dashboard'))

    # Jeśli to zajęcia cykliczne, pobierz wszystkie terminy z tego cyklu
    recurring_sessions = []
    if s.recurrence_group_id:
        recurring_sessions = TrainingSession.query.filter_by(
            recurrence_group_id=s.recurrence_group_id
        ).order_by(TrainingSession.date).all()

    # Dla każdego uczestnika sprawdź, na ile terminów jest zapisany
    bookings_with_info = []
    for booking in s.bookings.all():
        booking_info = {
            'booking': booking,
            'user': booking.user,
            'recurring_count': 0,
            'total_recurring': len(recurring_sessions) if recurring_sessions else 0
        }

        # Jeśli to zajęcia cykliczne, policz ile terminów zarezerwował
        if recurring_sessions:
            booking_info['recurring_count'] = Booking.query.filter(
                Booking.user_id == booking.user_id,
                Booking.session_id.in_([rs.id for rs in recurring_sessions])
            ).count()

        bookings_with_info.append(booking_info)

    return render_template("manage_session.html",
                           session=s,
                           bookings_with_info=bookings_with_info,
                           recurring_sessions=recurring_sessions)


@app.route("/cancel_booking/<int:booking_id>", methods=["POST"])
@login_required
@trainer_required
def cancel_booking(booking_id):
    b = db.session.get(Booking, booking_id)
    sid = b.session_id
    db.session.delete(b)
    db.session.commit()
    return redirect(url_for('manage_session', session_id=sid))


@app.route("/move_booking/<int:booking_id>", methods=["GET", "POST"])
@login_required
@trainer_required
def move_booking(booking_id):
    b = db.session.get(Booking, booking_id)
    if not b:
        flash("Nie znaleziono rezerwacji.", "danger")
        return redirect(url_for('trainer_dashboard'))

    form = MoveBookingForm(original_session_id=b.session_id)

    if form.validate_on_submit():
        new_session_id = form.new_session.data

        # Sprawdź czy użytkownik już ma rezerwację na nowe zajęcia
        existing = Booking.query.filter_by(user_id=b.user_id, session_id=new_session_id).first()
        if existing:
            flash("Użytkownik jest już zapisany na wybrane zajęcia.", "warning")
            return redirect(url_for('manage_session', session_id=b.session_id))

        # Przenieś rezerwację
        old_session_id = b.session_id
        b.session_id = new_session_id
        db.session.commit()
        flash("Przeniesiono rezerwację.", "success")
        return redirect(url_for('manage_session', session_id=old_session_id))

    return render_template("move_booking.html", form=form, user=b.user, session=b.session)


@app.route("/delete_session/<int:session_id>", methods=["POST"])
@login_required
@trainer_required
def delete_session(session_id):
    s = db.session.get(TrainingSession, session_id)
    if s and (current_user.is_admin or s.trainer_id == current_user.id):
        db.session.delete(s)
        db.session.commit()
        flash("Usunięto zajęcia.", "success")
    else:
        flash("Brak uprawnień do usunięcia tych zajęć.", "danger")
    return redirect(url_for('trainer_dashboard'))


@app.route("/delete_recurring_group/<group_id>", methods=["POST"])
@login_required
@trainer_required
def delete_recurring_group(group_id):
    sessions = TrainingSession.query.filter_by(recurrence_group_id=group_id).all()

    # Sprawdź uprawnienia
    if sessions and not current_user.is_admin:
        if sessions[0].trainer_id != current_user.id:
            flash("Brak uprawnień do usunięcia tych zajęć.", "danger")
            return redirect(url_for('trainer_dashboard'))

    for s in sessions:
        db.session.delete(s)
    db.session.commit()
    flash("Usunięto całą serię zajęć cyklicznych.", "success")
    return redirect(url_for('trainer_dashboard'))


@app.cli.command("create-accounts")
def create_accounts():
    data = [
        ("Menedżer", "admin@bodylab.pl", "admin123", "admin"),
        ("Arina Dziuba", "arina@bodylab.pl", "trener123", "trainer"),
        ("Laura Iwanowska", "laura@bodylab.pl", "trener123", "trainer"),
        ("Wiktoria Durtan", "wiktoria@bodylab.pl", "trener123", "trainer"),
        ("Jan Kowalski", "kowalski@gmail.com", "kowalski123", "user")
    ]
    for u, e, p, r in data:
        if not User.query.filter_by(email=e).first():
            new_u = User(username=u, email=e, role=r)
            new_u.set_password(p)
            db.session.add(new_u)
    db.session.commit()
    print("Gotowe. Konta utworzone.")


if __name__ == "__main__":
    app.run(debug=True, port=5001)