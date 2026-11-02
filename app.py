import os
import uuid
from datetime import datetime, timezone, timedelta

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
)
from werkzeug.utils import secure_filename
from pypdf import PdfReader
from dotenv import load_dotenv
from google import genai
from models import (
    db,
    User,
    StudyMaterial,
    Question,
    Exam,
    ExamQuestion,
    Course,
    TeacherCourse,
    StudentAttempt,
    StudentAnswer,
)
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import text

# ==================================================
# CONFIGURATION
# ==================================================

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY") or os.urandom(32)
# Other existing configuration...
# Set FLASK_SECRET_KEY in your .env file. The random fallback is safer than a
# hard-coded key, but sessions will reset whenever the app restarts.
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY") or os.urandom(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("COOKIE_SECURE", "false").lower() == "true"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=60)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
app.config["UPLOAD_FOLDER"] = os.path.join(
    app.root_path, "uploads"
)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
database_url = os.getenv("DATABASE_URL", "sqlite:///smartexam.db")

if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql+psycopg://", 1)
elif database_url.startswith("postgresql://"):
    database_url = database_url.replace("postgresql://", "postgresql+psycopg://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

ALLOWED_EXTENSIONS = {"pdf", "txt"}

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

api_key = os.getenv("GEMINI_API_KEY")
client = genai.Client(
    api_key=api_key,
    http_options={"timeout": 30000}
)if api_key else None
csrf = CSRFProtect(app)

db.init_app(app)


# ==================================================
# DATABASE INITIALIZATION
# ==================================================

with app.app_context():
    db.create_all()

    inspector = db.inspect(db.engine)

    if "study_material" in inspector.get_table_names():
        columns = {
            column["name"]
            for column in inspector.get_columns("study_material")
        }

        if "extracted_text" not in columns:
            with db.engine.begin() as connection:
                connection.exec_driver_sql(
                    "ALTER TABLE study_material "
                    "ADD COLUMN extracted_text TEXT"
                )

    # Safe, additive migration: existing accounts remain approved; new accounts
    # are explicitly marked pending by the registration route.
    user_columns = {
        column["name"] for column in db.inspect(db.engine).get_columns("user")
    }
    if "is_approved" not in user_columns:
        with db.engine.begin() as connection:
            connection.exec_driver_sql(
                'ALTER TABLE "user" ADD COLUMN is_approved BOOLEAN NOT NULL DEFAULT TRUE'
            )


# ==================================================
# TEXT EXTRACTION
# ==================================================

def extract_text_from_pdf(file_path):
    """Extract selectable text from a PDF."""

    try:
        reader = PdfReader(file_path)
        pages = []

        for page in reader.pages:
            try:
                text = page.extract_text(extraction_mode="layout")
            except TypeError:
                text = page.extract_text()

            if text and text.strip():
                pages.append(text.strip())

        extracted_text = "\n\n".join(pages).strip()

        app.logger.info(
            "PDF extraction: %s pages, %s characters",
            len(reader.pages),
            len(extracted_text),
        )

        if not extracted_text:
            app.logger.warning(
                "No selectable text found in PDF: %s",
                os.path.basename(file_path),
            )

        return extracted_text

    except Exception:
        app.logger.exception("PDF text extraction failed")
        return ""


def extract_text_from_txt(file_path):
    """Read a TXT file using common encodings."""

    for encoding in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            with open(file_path, "r", encoding=encoding) as file:
                return file.read().strip()
        except UnicodeDecodeError:
            continue

    return ""


# Validate every authenticated session against the database so changed roles,
# deleted users, or revoked approval do not retain access.
@app.before_request
def validate_authenticated_session():
    user_id = session.get("user_id")
    if user_id is None:
        return None
    user = db.session.get(User, user_id)
    if user is None:
        session.clear()
        return None
    approval = db.session.execute(
        db.text('SELECT is_approved FROM "user" WHERE id = :user_id'),
        {"user_id": user.id},
    ).first()
    if not approval or not bool(approval[0]):
        session.clear()
        flash("Your account is not approved. Please contact the administrator.")
        return redirect(url_for("login"))
    session["user_name"] = user.name
    session["user_role"] = user.role
    return None


# ==================================================
# HOME
# ==================================================

@app.route("/")
def home():
    return render_template("index.html")


# ==================================================
# REGISTRATION
# ==================================================

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "")

        if not name or not email or not password:
            flash("Please fill in all required fields.")
            return redirect(url_for("register"))

        if role not in ("teacher", "student"):
            flash("Please select a valid account role.")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must contain at least 8 characters.")
            return redirect(url_for("register"))

        if User.query.filter_by(email=email).first():
            flash("An account with this email already exists.")
            return redirect(url_for("register"))

        user = User(name=name, email=email, role=role)
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

                # New self-registered accounts require administrator approval.
        with db.engine.begin() as connection:
            connection.execute(
                text('UPDATE "user" SET is_approved = FALSE WHERE id = :user_id'),
                {"user_id": user.id},
            )

        flash("Account created. Please wait for an administrator to approve it before logging in.")
        return redirect(url_for("login"))
    return render_template("register.html")


# ==================================================
# LOGIN
# ==================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            approval_row = db.session.execute(
                db.text('SELECT is_approved FROM "user" WHERE id = :user_id'),
                {"user_id": user.id},
            ).first()

            # Legacy accounts are approved by the migration default.
            if not approval_row or not bool(approval_row[0]):
                flash("Your account is awaiting administrator approval.")
                return redirect(url_for("login"))

            session.clear()
            session.permanent = True
            session["user_id"] = user.id
            session["user_name"] = user.name
            session["user_role"] = user.role

            return redirect(url_for("dashboard"))

        flash("Invalid email or password.")
        return redirect(url_for("login"))

    return render_template("login.html")


# ==================================================
# DASHBOARD
# ==================================================

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        flash("Please log in to continue.")
        return redirect(url_for("login"))

    if session.get("user_role") == "admin":
        return redirect(url_for("admin_dashboard"))

    if session.get("user_role") == "student":
        return render_template("student_dashboard.html")

    return render_template("dashboard.html")


# ==================================================
# ADMIN DASHBOARD
# ==================================================

@app.route("/admin")
def admin_dashboard():
    if "user_id" not in session:
        flash("Please log in to continue.")
        return redirect(url_for("login"))

    if session.get("user_role") != "admin":
        flash("Administrator access required.")
        return redirect(url_for("dashboard"))

    total_users = User.query.count()
    total_teachers = User.query.filter_by(role="teacher").count()
    total_students = User.query.filter_by(role="student").count()
    total_courses = Course.query.count()
    total_exams = Exam.query.count()
    total_questions = Question.query.count()
    total_materials = StudyMaterial.query.count()
    pending_evaluations = StudentAttempt.query.filter_by(status="pending_evaluation").count()

    return render_template(
        "admin_dashboard.html",
        total_users=total_users,
        total_teachers=total_teachers,
        total_students=total_students,
        total_courses=total_courses,
        total_exams=total_exams,
        total_questions=total_questions,
        total_materials=total_materials,
        pending_evaluations=pending_evaluations,
    )


# ==================================================
# ADMIN: USER MANAGEMENT
# ==================================================

def _require_admin():
    """Return True only for a logged-in administrator."""
    if "user_id" not in session:
        flash("Please log in to continue.")
        return False
    if session.get("user_role") != "admin":
        flash("Administrator access required.")
        return False
    return True

@app.route("/admin/create-admin", methods=["GET", "POST"])
def create_admin():
    if not _require_admin():
        return redirect(
            url_for("login" if "user_id" not in session else "dashboard")
        )

    # Display the separate Create Admin page.
    if request.method == "GET":
        return render_template("create_admin.html")

    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    if not name or not email or not password:
        flash("Please fill in all fields.")
        return redirect(url_for("create_admin"))

    if len(password) < 8:
        flash("Password must contain at least 8 characters.")
        return redirect(url_for("create_admin"))

    if User.query.filter_by(email=email).first():
        flash("An account with this email already exists.")
        return redirect(url_for("create_admin"))

    try:
        new_admin = User(
            name=name,
            email=email,
            role="admin"
        )
        new_admin.set_password(password)

        db.session.add(new_admin)
        db.session.commit()
        with db.engine.begin() as connection:
            connection.execute(
                text('UPDATE "user" SET is_approved = TRUE WHERE id = :user_id'),
                {"user_id": new_admin.id},
            )

        flash(f"Administrator account created for {name}.")
        return redirect(url_for("admin_dashboard"))
    except Exception:
        db.session.rollback()
        app.logger.exception("Admin account creation failed")
        flash("Could not create the administrator account.")
        return redirect(url_for("create_admin"))


@app.route("/admin/users")
def admin_users():
    if not _require_admin():
        return redirect(url_for("login" if "user_id" not in session else "dashboard"))
    users = User.query.order_by(User.role.asc(), User.name.asc()).all()
    return render_template("admin_users.html", users=users, current_user_id=session["user_id"])


@app.route("/admin/pending-users")
def admin_pending_users():
    if not _require_admin():
        return redirect(url_for("login" if "user_id" not in session else "dashboard"))

    pending_users = User.query.filter(
        User.role.in_(("teacher", "student"))
    ).order_by(User.name.asc()).all()
    approval_map = {}
    rows = db.session.execute(
        db.text('SELECT id, is_approved FROM "user"')
    ).all()
    approval_map = {row[0]: bool(row[1]) for row in rows}
    pending_users = [user for user in pending_users if not approval_map.get(user.id, True)]
    return render_template("admin_pending_users.html", users=pending_users)


@app.route("/admin/users/<int:user_id>/approval", methods=["POST"])
def admin_update_user_approval(user_id):
    if not _require_admin():
        return redirect(url_for("login" if "user_id" not in session else "dashboard"))

    user = User.query.get_or_404(user_id)
    if user.role not in {"teacher", "student"}:
        flash("Administrator accounts cannot be approved or changed here.")
        return redirect(url_for("admin_pending_users"))

    action = request.form.get("action", "").strip().lower()
    if action not in {"approve", "reject"}:
        flash("Invalid approval action.")
        return redirect(url_for("admin_pending_users"))
    if action == "approve":
        with db.engine.begin() as connection:
            connection.execute(
                text('UPDATE "user" SET is_approved = TRUE WHERE id = :user_id'),
                {"user_id": user.id},
            )
        flash(f"Account approved for {user.name}.")
    else:
        # Rejecting removes only the pending account, never an approved account.
        approved_row = db.session.execute(
            db.text('SELECT is_approved FROM "user" WHERE id = :user_id'),
            {"user_id": user.id},
        ).first()
        if approved_row and bool(approved_row[0]):
            flash("Only pending accounts can be rejected from this page.")
            return redirect(url_for("admin_pending_users"))
        try:
            db.session.delete(user)
            db.session.commit()
            flash("Pending account rejected and deleted.")
        except Exception:
            db.session.rollback()
            app.logger.exception("Pending account rejection failed")
            flash("Could not reject the account.")

    return redirect(url_for("admin_pending_users"))


@app.route("/admin/users/<int:user_id>/role", methods=["POST"])
def admin_update_user_role(user_id):
    if not _require_admin():
        return redirect(url_for("login" if "user_id" not in session else "dashboard"))
    user = User.query.get_or_404(user_id)
    new_role = request.form.get("role", "").strip().lower()
    if user.id == session["user_id"]:
        flash("You cannot change your own administrator role.")
    elif user.role == "admin":
        flash("Administrator accounts cannot be changed from this page.")
    elif new_role not in {"teacher", "student"}:
        flash("Choose a valid role.")
    else:
        user.role = new_role
        try:
            db.session.commit()
            flash(f"Role updated for {user.name}.")
        except Exception:
            db.session.rollback()
            app.logger.exception("Admin role update failed")
            flash("Could not update the role.")
    return redirect(url_for("admin_users"))


# ==================================================
# ADMIN: COURSE MANAGEMENT
# ==================================================

@app.route("/admin/courses", methods=["GET", "POST"])
def admin_courses():
    if not _require_admin():
        return redirect(url_for("login" if "user_id" not in session else "dashboard"))
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        code = request.form.get("code", "").strip().upper()
        description = request.form.get("description", "").strip()
        if not name or not code:
            flash("Course name and course code are required.")
        elif Course.query.filter(db.or_(Course.name.ilike(name), Course.code.ilike(code))).first():
            flash("A course with that name or code already exists.")
        else:
            db.session.add(Course(name=name, code=code, description=description or None))
            try:
                db.session.commit()
                flash("Course created successfully.")
            except Exception:
                db.session.rollback()
                app.logger.exception("Course creation failed")
                flash("Could not create the course.")
        return redirect(url_for("admin_courses"))
    courses = Course.query.order_by(Course.name.asc()).all()
    return render_template("admin_courses.html", courses=courses)


@app.route("/admin/courses/<int:course_id>/delete", methods=["POST"])
def admin_delete_course(course_id):
    if not _require_admin():
        return redirect(url_for("login" if "user_id" not in session else "dashboard"))
    course = Course.query.get_or_404(course_id)
    if course.teacher_assignments:
        flash("Remove teacher assignments before deleting this course.")
    else:
        try:
            db.session.delete(course)
            db.session.commit()
            flash("Course deleted.")
        except Exception:
            db.session.rollback()
            app.logger.exception("Course deletion failed")
            flash("Could not delete the course.")
    return redirect(url_for("admin_courses"))


# ==================================================
# ADMIN: TEACHER-COURSE ASSIGNMENTS
# ==================================================

@app.route("/admin/assignments", methods=["GET", "POST"])
def admin_assignments():
    if not _require_admin():
        return redirect(url_for("login" if "user_id" not in session else "dashboard"))
    if request.method == "POST":
        teacher_id = request.form.get("teacher_id", type=int)
        course_id = request.form.get("course_id", type=int)
        teacher = User.query.filter_by(id=teacher_id, role="teacher").first()
        course = Course.query.get(course_id) if course_id else None
        if not teacher or not course:
            flash("Choose a valid teacher and course.")
        elif TeacherCourse.query.filter_by(teacher_id=teacher.id, course_id=course.id).first():
            flash("This teacher is already assigned to that course.")
        else:
            db.session.add(TeacherCourse(teacher_id=teacher.id, course_id=course.id))
            try:
                db.session.commit()
                flash(f"Assigned {teacher.name} to {course.name}.")
            except Exception:
                db.session.rollback()
                app.logger.exception("Teacher-course assignment failed")
                flash("Could not save the assignment.")
        return redirect(url_for("admin_assignments"))
    teachers = User.query.filter_by(role="teacher").order_by(User.name.asc()).all()
    courses = Course.query.order_by(Course.name.asc()).all()
    assignments = TeacherCourse.query.join(User, TeacherCourse.teacher_id == User.id).join(Course, TeacherCourse.course_id == Course.id).order_by(Course.name.asc(), User.name.asc()).all()
    return render_template("admin_assignments.html", teachers=teachers, courses=courses, assignments=assignments)


@app.route("/admin/assignments/<int:assignment_id>/delete", methods=["POST"])
def admin_delete_assignment(assignment_id):
    if not _require_admin():
        return redirect(url_for("login" if "user_id" not in session else "dashboard"))
    assignment = TeacherCourse.query.get_or_404(assignment_id)
    db.session.delete(assignment)
    try:
        db.session.commit()
        flash("Teacher-course assignment removed.")
    except Exception:
        db.session.rollback()
        app.logger.exception("Assignment removal failed")
        flash("Could not remove the assignment.")
    return redirect(url_for("admin_assignments"))


# ==================================================
# ADMIN: EXAMINATION REPORTS
# ==================================================

@app.route("/admin/reports")
def admin_reports():
    if not _require_admin():
        return redirect(url_for("login" if "user_id" not in session else "dashboard"))
    exams = Exam.query.order_by(Exam.created_at.desc(), Exam.id.desc()).all()
    report_rows = []
    for exam in exams:
        attempts = StudentAttempt.query.filter_by(exam_id=exam.id).order_by(StudentAttempt.id.desc()).all()
        report_rows.append({
            "exam": exam,
            "attempt_count": len(attempts),
            "submitted_count": sum(1 for a in attempts if a.submitted_at is not None),
            "pending_count": sum(1 for a in attempts if a.status == "pending_evaluation"),
            "evaluated_count": sum(1 for a in attempts if a.status == "evaluated"),
            "attempts": attempts,
        })
    return render_template("admin_reports.html", report_rows=report_rows)


# ==================================================
# ADMIN: SYSTEM OVERVIEW
# ==================================================

@app.route("/admin/settings")
def admin_settings():
    if not _require_admin():
        return redirect(url_for("login" if "user_id" not in session else "dashboard"))
    return render_template("admin_settings.html")


# ==================================================
# LOGOUT
# ==================================================

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("login"))


# ==================================================
# UPLOAD STUDY MATERIAL
# ==================================================

@app.route("/upload", methods=["GET", "POST"])
def upload_material():
    if "user_id" not in session:
        flash("Please log in to continue.")
        return redirect(url_for("login"))

    if session.get("user_role") != "teacher":
        flash("Only teachers can upload study materials.")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        uploaded_file = request.files.get("file")

        if not title or not uploaded_file or not uploaded_file.filename:
            flash("Enter a title and select a file.")
            return redirect(url_for("upload_material"))

        original_filename = secure_filename(uploaded_file.filename)

        if not original_filename or "." not in original_filename:
            flash("Please select a valid PDF or TXT file.")
            return redirect(url_for("upload_material"))

        extension = original_filename.rsplit(".", 1)[1].lower()

        if extension not in ALLOWED_EXTENSIONS:
            flash("Only PDF and TXT files are allowed.")
            return redirect(url_for("upload_material"))

        stored_filename = f"{uuid.uuid4().hex}_{original_filename}"

        saved_path = os.path.join(
            app.config["UPLOAD_FOLDER"],
            stored_filename,
        )

        try:
            uploaded_file.save(saved_path)

            if extension == "pdf":
                extracted_text = extract_text_from_pdf(saved_path)
            else:
                extracted_text = extract_text_from_txt(saved_path)

            material = StudyMaterial(
                title=title,
                filename=stored_filename,
                extracted_text=extracted_text,
                uploaded_by=session["user_id"],
            )

            db.session.add(material)
            db.session.commit()

            if extracted_text:
                flash(
                    f"'{title}' uploaded successfully! "
                    f"Extracted {len(extracted_text)} characters."
                )
            else:
                flash(
                    f"'{title}' was uploaded, but no readable text "
                    "was extracted. Scanned PDFs may require OCR."
                )

        except Exception:
            db.session.rollback()

            if os.path.exists(saved_path):
                try:
                    os.remove(saved_path)
                except OSError:
                    app.logger.exception(
                        "Could not remove failed upload"
                    )

            app.logger.exception("Material upload failed")
            flash("Upload failed. Check the VS Code terminal.")
            return redirect(url_for("upload_material"))

        return redirect(url_for("upload_material"))

    materials = StudyMaterial.query.filter_by(
        uploaded_by=session["user_id"]
    ).order_by(StudyMaterial.id.desc()).all()

    return render_template(
        "upload.html",
        materials=materials,
    )


# ==================================================
# VIEW EXTRACTED TEXT
# ==================================================

@app.route("/material/<int:material_id>")
def view_material(material_id):
    if "user_id" not in session:
        flash("Please log in to continue.")
        return redirect(url_for("login"))

    material = StudyMaterial.query.filter_by(
        id=material_id,
        uploaded_by=session["user_id"],
    ).first_or_404()

    return render_template(
        "material.html",
        material=material,
    )


# ==================================================
# AI QUESTION GENERATION
# ==================================================

@app.route("/generate-questions", methods=["GET", "POST"])
def generate_questions():
    if "user_id" not in session:
        flash("Please log in to continue.")
        return redirect(url_for("login"))

    if session.get("user_role") != "teacher":
        flash("Only teachers can generate questions.")
        return redirect(url_for("dashboard"))

    materials = StudyMaterial.query.filter_by(
        uploaded_by=session["user_id"]
    ).order_by(StudyMaterial.id.desc()).all()

    if request.method == "POST":
        import json

        material_id = request.form.get("material_id", type=int)
        question_type = request.form.get("question_type", "")
        difficulty = request.form.get("difficulty", "")
        question_count = request.form.get("question_count", type=int)
        marks = request.form.get("marks", type=int)

        material = StudyMaterial.query.filter_by(
            id=material_id,
            uploaded_by=session["user_id"],
        ).first()

        if not material or not (material.extracted_text or "").strip():
            flash("No extracted text is available for this material.")
            return redirect(url_for("generate_questions"))

        allowed_types = {
            "MCQ",
            "True/False",
            "Short Answer",
            "Long Answer",
        }

        if (
            question_type not in allowed_types
            or difficulty not in {"Easy", "Medium", "Hard"}
            or question_count is None
            or not 1 <= question_count <= 20
            or marks is None
            or not 1 <= marks <= 100
        ):
            flash("Please enter valid question-generation settings.")
            return redirect(url_for("generate_questions"))

        if client is None:
            flash("Gemini API key is missing from your .env file.")
            return redirect(url_for("generate_questions"))

        prompt = f"""
Generate exactly {question_count} questions using only the study material.

Return ONLY a valid JSON object in this format:
{{
  "questions": [
    {{
      "question_text": "Question text",
      "option_a": "Option A or null",
      "option_b": "Option B or null",
      "option_c": "Option C or null",
      "option_d": "Option D or null",
      "correct_answer": "Correct answer",
      "explanation": "Brief explanation"
    }}
  ]
}}

Question type: {question_type}
Difficulty: {difficulty}
Marks per question: {marks}

For MCQ, provide four options.
For True/False, provide the correct answer as True or False.
For Short Answer and Long Answer, provide a model answer in correct_answer.
Use null for options that do not apply.

Study material:
{material.extracted_text[:20000]}
"""

        try:
            response = client.models.generate_content(
                model="gemini-3.5-flash-lite",
                contents=prompt,
                config={
                    "response_mime_type": "application/json",
                    "temperature": 0.2,
                    "max_output_tokens": 2048,
                },
            )

            generated_text = (response.text or "").strip()

            if not generated_text:
                flash("Gemini returned no questions. Please try again.")
                return redirect(url_for("generate_questions"))

            data = json.loads(generated_text)
            generated_questions = data.get("questions", [])

            if (
                not isinstance(generated_questions, list)
                or len(generated_questions) != question_count
            ):
                flash("The AI returned an unexpected number of questions. Please try again.")
                return redirect(url_for("generate_questions"))

            saved_questions = []

            for item in generated_questions:
                if not isinstance(item, dict):
                    raise ValueError("Invalid question format.")

                question_text = str(item.get("question_text") or "").strip()
                correct_answer = str(item.get("correct_answer") or "").strip()

                if not question_text or not correct_answer:
                    raise ValueError("A question or answer is missing.")

                question = Question(
                    question_text=question_text,
                    question_type=question_type,
                    difficulty=difficulty,
                    option_a=item.get("option_a"),
                    option_b=item.get("option_b"),
                    option_c=item.get("option_c"),
                    option_d=item.get("option_d"),
                    correct_answer=correct_answer,
                    explanation=str(item.get("explanation") or ""),
                    marks=marks,
                    status="pending",
                    created_by=session["user_id"],
                    material_id=material.id,
                )

                saved_questions.append(question)

            db.session.add_all(saved_questions)
            db.session.commit()

            flash(
                f"{len(saved_questions)} questions saved for teacher review."
            )

            return render_template(
                "generated_questions.html",
                material=material,
                generated_text=generated_text,
                question_type=question_type,
                difficulty=difficulty,
                question_count=question_count,
                marks=marks,
                saved_questions=saved_questions,
            )

        except Exception as error:
            db.session.rollback()
            app.logger.exception("Question generation or saving failed")

            error_text = str(error).lower()
            if "503" in error_text or "unavailable" in error_text or "high demand" in error_text:
                flash(
                    "Gemini is temporarily busy. Please wait a minute and try again. "
                    "Your questions have not been saved."
                )
            elif "504" in error_text or "deadline_exceeded" in error_text or "timeout" in error_text:
                flash(
                    "Gemini took too long to respond. Try one question using a shorter study material."
                )
            else:
                flash(
                    f"Question generation failed ({type(error).__name__}). "
                    "Check the VS Code terminal for details."
                )
            return redirect(url_for("generate_questions"))

    return render_template(
        "generate_questions.html",
        materials=materials,
    )
# ==================================================
# REVIEW AND APPROVE QUESTIONS
# ==================================================

@app.route("/review-questions")
def review_questions():
    if "user_id" not in session:
        flash("Please log in to continue.")
        return redirect(url_for("login"))

    if session.get("user_role") != "teacher":
        flash("Only teachers can review questions.")
        return redirect(url_for("dashboard"))

    questions = Question.query.filter_by(
        created_by=session["user_id"],
        status="pending"
    ).order_by(Question.id.desc()).all()

    return render_template(
        "review_questions.html",
        questions=questions
    )


@app.route("/review-questions/<int:question_id>/<action>", methods=["POST"])
def update_question_status(question_id, action):
    if "user_id" not in session:
        flash("Please log in to continue.")
        return redirect(url_for("login"))

    if session.get("user_role") != "teacher":
        flash("Only teachers can review questions.")
        return redirect(url_for("dashboard"))

    if action not in ("approve", "reject"):
        flash("Invalid action.")
        return redirect(url_for("review_questions"))

    question = Question.query.filter_by(
        id=question_id,
        created_by=session["user_id"],
        status="pending"
    ).first_or_404()

    question.status = (
        "approved" if action == "approve" else "rejected"
    )

    db.session.commit()

    if action == "approve":
        flash("Question approved and added to the Question Bank!")
    else:
        flash("Question rejected.")

    return redirect(url_for("review_questions"))
# ==================================================
# EXAM BUILDER
# ==================================================

@app.route("/exams", methods=["GET", "POST"])
def exam_builder():
    if "user_id" not in session:
        flash("Please log in to continue.")
        return redirect(url_for("login"))

    if session.get("user_role") != "teacher":
        flash("Only teachers can create examinations.")
        return redirect(url_for("dashboard"))

    approved_questions = Question.query.filter_by(
        created_by=session["user_id"],
        status="approved"
    ).order_by(Question.id.desc()).all()

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        duration = request.form.get("duration_minutes", type=int)
        selected_ids = request.form.getlist("question_ids", type=int)

        if not title:
            flash("Please enter an examination title.")
            return redirect(url_for("exam_builder"))

        if duration is None or not 1 <= duration <= 600:
            flash("Duration must be between 1 and 600 minutes.")
            return redirect(url_for("exam_builder"))

        if not selected_ids:
            flash("Please select at least one approved question.")
            return redirect(url_for("exam_builder"))

        selected_questions = Question.query.filter(
            Question.id.in_(selected_ids),
            Question.created_by == session["user_id"],
            Question.status == "approved"
        ).all()

        questions_by_id = {question.id: question for question in selected_questions}
        if len(questions_by_id) != len(set(selected_ids)):
            flash("One or more selected questions are invalid.")
            return redirect(url_for("exam_builder"))

        exam = Exam(
            title=title,
            description=description,
            duration_minutes=duration,
            total_marks=sum(questions_by_id[qid].marks for qid in selected_ids),
            status="draft",
            created_by=session["user_id"]
        )

        try:
            db.session.add(exam)
            db.session.flush()

            for position, question_id in enumerate(selected_ids, start=1):
                db.session.add(
                    ExamQuestion(
                        exam_id=exam.id,
                        question_id=question_id,
                        position=position
                    )
                )

            db.session.commit()
            flash(f"Exam '{title}' saved successfully as a draft!")
            return redirect(url_for("exam_builder"))

        except Exception:
            db.session.rollback()
            app.logger.exception("Exam creation failed")
            flash("Could not save the exam. Check the VS Code terminal.")
            return redirect(url_for("exam_builder"))

    exams = Exam.query.filter_by(
        created_by=session["user_id"]
    ).order_by(Exam.id.desc()).all()

    return render_template(
        "exam_builder.html",
        questions=approved_questions,
        exams=exams,
        edit_exam=None
    )


@app.route("/exams/<int:exam_id>/edit", methods=["GET", "POST"])
def edit_exam(exam_id):
    if "user_id" not in session:
        flash("Please log in to continue.")
        return redirect(url_for("login"))

    if session.get("user_role") != "teacher":
        flash("Only teachers can edit examinations.")
        return redirect(url_for("dashboard"))

    exam = Exam.query.filter_by(
        id=exam_id,
        created_by=session["user_id"]
    ).first_or_404()

    if exam.status != "draft":
        flash("Only draft exams can be edited.")
        return redirect(url_for("exam_builder"))

    approved_questions = Question.query.filter_by(
        created_by=session["user_id"],
        status="approved"
    ).order_by(Question.id.desc()).all()

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        duration = request.form.get("duration_minutes", type=int)
        selected_ids = request.form.getlist("question_ids", type=int)

        if not title:
            flash("Please enter an examination title.")
        elif duration is None or not 1 <= duration <= 600:
            flash("Duration must be between 1 and 600 minutes.")
        elif not selected_ids:
            flash("Please select at least one approved question.")
        else:
            selected_questions = Question.query.filter(
                Question.id.in_(set(selected_ids)),
                Question.created_by == session["user_id"],
                Question.status == "approved"
            ).all()
            questions_by_id = {
                question.id: question for question in selected_questions
            }

            if len(questions_by_id) != len(set(selected_ids)):
                flash("One or more selected questions are invalid.")
            else:
                try:
                    exam.title = title
                    exam.description = description
                    exam.duration_minutes = duration
                    exam.total_marks = sum(
                        questions_by_id[qid].marks for qid in selected_ids
                    )

                    # Replace the draft's question list with the selected list.
                    ExamQuestion.query.filter_by(exam_id=exam.id).delete(
                        synchronize_session=False
                    )
                    for position, question_id in enumerate(selected_ids, start=1):
                        db.session.add(
                            ExamQuestion(
                                exam_id=exam.id,
                                question_id=question_id,
                                position=position
                            )
                        )

                    db.session.commit()
                    flash(f"Draft '{exam.title}' updated successfully!")
                    return redirect(url_for("exam_builder"))
                except Exception:
                    db.session.rollback()
                    app.logger.exception("Draft exam update failed")
                    flash("Could not update the draft. Check the VS Code terminal.")

        # Re-render the editor so the teacher does not lose the form values.
        exam.title = title
        exam.description = description
        exam.duration_minutes = duration if duration is not None else exam.duration_minutes

    exams = Exam.query.filter_by(
        created_by=session["user_id"]
    ).order_by(Exam.id.desc()).all()

    selected_question_ids = {
        item.question_id for item in exam.questions
        if getattr(item, "question_id", None) is not None
    }

    return render_template(
        "exam_builder.html",
        questions=approved_questions,
        exams=exams,
        edit_exam=exam,
        selected_question_ids=selected_question_ids
    )


# ==================================================
# PUBLISH EXAM
# ==================================================

@app.route("/exams/<int:exam_id>/publish", methods=["POST"])
def publish_exam(exam_id):
    if "user_id" not in session:
        flash("Please log in to continue.")
        return redirect(url_for("login"))

    if session.get("user_role") != "teacher":
        flash("Only teachers can publish exams.")
        return redirect(url_for("dashboard"))

    exam = Exam.query.filter_by(
        id=exam_id,
        created_by=session["user_id"]
    ).first_or_404()

    if exam.status != "draft":
        flash("Only draft exams can be published.")
        return redirect(url_for("exam_builder"))

    if not exam.questions:
        flash("Add questions before publishing the exam.")
        return redirect(url_for("exam_builder"))

    exam.status = "published"

    try:
        db.session.commit()
        flash(f"Exam '{exam.title}' published successfully!")
    except Exception:
        db.session.rollback()
        app.logger.exception("Failed to publish exam")
        flash("Could not publish the exam. Please try again.")

    return redirect(url_for("exam_builder"))

# ==================================================
# QUESTION BANK
# ==================================================

@app.route("/question-bank")
def question_bank():
    if "user_id" not in session:
        flash("Please log in to continue.")
        return redirect(url_for("login"))

    if session.get("user_role") != "teacher":
        flash("Only teachers can access the Question Bank.")
        return redirect(url_for("dashboard"))

    questions = Question.query.filter_by(
        created_by=session["user_id"],
        status="approved"
    ).order_by(Question.id.desc()).all()

    return render_template(
        "question_bank.html",
        questions=questions
    )



# ==================================================
# STUDENT EXAMINATION AND RESULTS
# ==================================================

def _utc_now():
    return datetime.now(timezone.utc)


def _as_utc(value):
    """SQLite may return a naive datetime; interpret stored values as UTC."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _normalise_answer(value):
    return " ".join(str(value or "").strip().casefold().split())


def _objective_answer_is_correct(question, submitted_answer):
    submitted = _normalise_answer(submitted_answer)
    correct = _normalise_answer(question.correct_answer)

    if question.question_type == "True/False":
        aliases = {
            "true": {"true", "t", "yes"},
            "false": {"false", "f", "no"},
        }
        submitted = next((key for key, values in aliases.items() if submitted in values), submitted)
        correct = next((key for key, values in aliases.items() if correct in values), correct)
        return submitted == correct

    if question.question_type == "MCQ":
        options = {
            "a": question.option_a,
            "b": question.option_b,
            "c": question.option_c,
            "d": question.option_d,
        }
        # If the model answer is a letter, compare against that option's text.
        if correct in options and options[correct]:
            correct = _normalise_answer(options[correct])
        # Accept either the option letter or its displayed text from the student.
        if submitted in options and options[submitted]:
            submitted = _normalise_answer(options[submitted])
        return submitted == correct

    return False


def _attempt_remaining_seconds(attempt, duration_minutes):
    started = _as_utc(attempt.started_at)
    elapsed = max(0, int((_utc_now() - started).total_seconds()))
    return max(0, duration_minutes * 60 - elapsed)


def _calculate_attempt_score(attempt):
    # Query after flush so newly-created answers are included in the score.
    answers = StudentAnswer.query.filter_by(attempt_id=attempt.id).all()
    return sum(float(answer.marks_awarded or 0) for answer in answers)


@app.route("/student/exams")
def student_exams():
    if "user_id" not in session:
        flash("Please log in to continue.")
        return redirect(url_for("login"))
    if session.get("user_role") != "student":
        flash("Only students can access available examinations.")
        return redirect(url_for("dashboard"))

    exams = Exam.query.filter_by(status="published").order_by(Exam.id.desc()).all()
    attempts = {
        attempt.exam_id: attempt
        for attempt in StudentAttempt.query.filter_by(
            student_id=session["user_id"]
        ).order_by(StudentAttempt.id.desc()).all()
    }
    return render_template("student_exams.html", exams=exams, attempts=attempts)


@app.route("/student/exams/<int:exam_id>/take", methods=["GET", "POST"])
def take_exam(exam_id):
    if "user_id" not in session:
        flash("Please log in to continue.")
        return redirect(url_for("login"))
    if session.get("user_role") != "student":
        flash("Only students can take examinations.")
        return redirect(url_for("dashboard"))

    exam = Exam.query.filter_by(id=exam_id, status="published").first_or_404()
    existing_attempt = StudentAttempt.query.filter_by(
        student_id=session["user_id"],
        exam_id=exam.id
    ).order_by(StudentAttempt.id.desc()).first()

    if existing_attempt and existing_attempt.status != "in_progress":
        flash("You have already submitted this examination.")
        return redirect(url_for("student_results"))

    if existing_attempt is None:
        existing_attempt = StudentAttempt(
            student_id=session["user_id"],
            exam_id=exam.id,
            status="in_progress"
        )
        db.session.add(existing_attempt)
        db.session.commit()

    exam_questions = list(exam.questions)
    questions = [item.question for item in exam_questions if item.question is not None]
    if not questions:
        flash("This examination has no available questions.")
        return redirect(url_for("student_exams"))

    if request.method == "POST":
        remaining = _attempt_remaining_seconds(existing_attempt, exam.duration_minutes)
        # If the timer expired, still accept the submitted form, but never extend the attempt.
        submitted_question_ids = {q.id for q in questions}
        existing_answers = {
            answer.question_id: answer
            for answer in StudentAnswer.query.filter_by(attempt_id=existing_attempt.id).all()
        }

        for question in questions:
            answer_text = request.form.get(f"answer_{question.id}", "").strip()
            answer = existing_answers.get(question.id)
            if answer is None:
                answer = StudentAnswer(
                    attempt_id=existing_attempt.id,
                    question_id=question.id
                )
                db.session.add(answer)
            answer.answer_text = answer_text

            if question.question_type in {"MCQ", "True/False"}:
                answer.marks_awarded = (
                    float(question.marks)
                    if _objective_answer_is_correct(question, answer_text)
                    else 0.0
                )
            else:
                # Short and long answers require teacher review.
                answer.marks_awarded = None

        # Do not allow answers to questions that are not part of this exam.
        for answer in list(existing_attempt.answers):
            if answer.question_id not in submitted_question_ids:
                db.session.delete(answer)

        db.session.flush()
        existing_attempt.submitted_at = _utc_now().replace(tzinfo=None)
        subjective_pending = any(
            q.question_type not in {"MCQ", "True/False"} for q in questions
        )
        existing_attempt.score = _calculate_attempt_score(existing_attempt)
        existing_attempt.status = "pending_evaluation" if subjective_pending else "evaluated"

        try:
            db.session.commit()
            flash(
                "Exam submitted. Your objective answers were marked automatically."
                if subjective_pending
                else "Exam submitted and evaluated successfully."
            )
            return redirect(url_for("student_results"))
        except Exception:
            db.session.rollback()
            app.logger.exception("Student exam submission failed")
            flash("Could not submit your exam. Please try again.")
            return redirect(url_for("take_exam", exam_id=exam.id))

    remaining_seconds = _attempt_remaining_seconds(existing_attempt, exam.duration_minutes)
    saved_answers = {
        answer.question_id: answer.answer_text
        for answer in StudentAnswer.query.filter_by(attempt_id=existing_attempt.id).all()
    }
    return render_template(
        "take_exam.html",
        exam=exam,
        questions=questions,
        remaining_seconds=remaining_seconds,
        saved_answers=saved_answers
    )


@app.route("/student/results")
def student_results():
    if "user_id" not in session:
        flash("Please log in to continue.")
        return redirect(url_for("login"))
    if session.get("user_role") != "student":
        flash("Only students can view student results.")
        return redirect(url_for("dashboard"))

    attempts = StudentAttempt.query.filter_by(
        student_id=session["user_id"]
    ).order_by(StudentAttempt.id.desc()).all()
    return render_template("student_results.html", attempts=attempts)


@app.route("/teacher/evaluation")
def teacher_evaluation():
    if "user_id" not in session:
        flash("Please log in to continue.")
        return redirect(url_for("login"))
    if session.get("user_role") != "teacher":
        flash("Only teachers can evaluate student answers.")
        return redirect(url_for("dashboard"))

    attempts = (
        StudentAttempt.query
        .join(Exam, StudentAttempt.exam_id == Exam.id)
        .filter(
            Exam.created_by == session["user_id"],
            StudentAttempt.status == "pending_evaluation"
        )
        .order_by(StudentAttempt.submitted_at.asc())
        .all()
    )
    return render_template("teacher_evaluation.html", attempts=attempts)


@app.route("/teacher/evaluation/<int:attempt_id>", methods=["GET", "POST"])
def evaluate_attempt(attempt_id):
    if "user_id" not in session:
        flash("Please log in to continue.")
        return redirect(url_for("login"))
    if session.get("user_role") != "teacher":
        flash("Only teachers can evaluate student answers.")
        return redirect(url_for("dashboard"))

    attempt = (
        StudentAttempt.query
        .join(Exam, StudentAttempt.exam_id == Exam.id)
        .filter(
            StudentAttempt.id == attempt_id,
            Exam.created_by == session["user_id"]
        )
        .first_or_404()
    )
    subjective_answers = [
        answer for answer in attempt.answers
        if answer.question.question_type not in {"MCQ", "True/False"}
    ]

    if request.method == "POST":
        for answer in subjective_answers:
            raw_marks = request.form.get(f"marks_{answer.id}", "").strip()
            try:
                marks = float(raw_marks)
            except (TypeError, ValueError):
                flash("Enter a valid mark for every written answer.")
                return redirect(url_for("evaluate_attempt", attempt_id=attempt.id))

            max_marks = float(answer.question.marks)
            if marks < 0 or marks > max_marks:
                flash(f"Marks must be between 0 and {max_marks:g}.")
                return redirect(url_for("evaluate_attempt", attempt_id=attempt.id))
            answer.marks_awarded = marks

        attempt.score = _calculate_attempt_score(attempt)
        attempt.status = (
            "evaluated"
            if all(answer.marks_awarded is not None for answer in subjective_answers)
            else "pending_evaluation"
        )

        try:
            db.session.commit()
            flash("Evaluation saved successfully.")
            return redirect(url_for("teacher_evaluation"))
        except Exception:
            db.session.rollback()
            app.logger.exception("Manual evaluation failed")
            flash("Could not save marks. Please try again.")
            return redirect(url_for("evaluate_attempt", attempt_id=attempt.id))

    return render_template(
        "evaluate_attempt.html",
        attempt=attempt,
        subjective_answers=subjective_answers
    )


# ==================================================
# RUN APPLICATION
# ==================================================

if __name__ == "__main__":
    app.run(debug=False, use_reloader=False)