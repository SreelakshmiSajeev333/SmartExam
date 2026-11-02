from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone

db = SQLAlchemy()


# ==================================================
# USER MODEL
# ==================================================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False)

    # New self-registered teachers/students wait for administrator approval.
    # Existing databases are upgraded by the migration in app.py.
    is_approved = db.Column(db.Boolean, nullable=False, default=True)

    courses = db.relationship(
        "TeacherCourse",
        back_populates="teacher",
        cascade="all, delete-orphan",
        foreign_keys="TeacherCourse.teacher_id"
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# ==================================================
# COURSE MODEL
# ==================================================

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False, unique=True)
    code = db.Column(db.String(30), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=True)

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc)
    )

    teacher_assignments = db.relationship(
        "TeacherCourse",
        back_populates="course",
        cascade="all, delete-orphan"
    )


# ==================================================
# TEACHER-COURSE ASSIGNMENT MODEL
# ==================================================

class TeacherCourse(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    teacher_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    course_id = db.Column(
        db.Integer,
        db.ForeignKey("course.id"),
        nullable=False
    )

    assigned_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc)
    )

    teacher = db.relationship(
        "User",
        back_populates="courses",
        foreign_keys=[teacher_id]
    )

    course = db.relationship(
        "Course",
        back_populates="teacher_assignments"
    )

    __table_args__ = (
        db.UniqueConstraint(
            "teacher_id",
            "course_id",
            name="unique_teacher_course"
        ),
    )


# ==================================================
# STUDY MATERIAL MODEL
# ==================================================

class StudyMaterial(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    extracted_text = db.Column(db.Text, nullable=True)

    uploaded_by = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    uploaded_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc)
    )


# ==================================================
# QUESTION MODEL
# ==================================================

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    question_text = db.Column(db.Text, nullable=False)
    question_type = db.Column(db.String(30), nullable=False)
    difficulty = db.Column(db.String(20), nullable=False)

    option_a = db.Column(db.Text, nullable=True)
    option_b = db.Column(db.Text, nullable=True)
    option_c = db.Column(db.Text, nullable=True)
    option_d = db.Column(db.Text, nullable=True)

    correct_answer = db.Column(db.Text, nullable=True)
    explanation = db.Column(db.Text, nullable=True)
    marks = db.Column(db.Integer, nullable=False, default=1)

    status = db.Column(
        db.String(20),
        nullable=False,
        default="pending"
    )

    created_by = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    material_id = db.Column(
        db.Integer,
        db.ForeignKey("study_material.id"),
        nullable=True
    )

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc)
    )


# ==================================================
# EXAM MODEL
# ==================================================

class Exam(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)

    duration_minutes = db.Column(
        db.Integer,
        nullable=False,
        default=60
    )

    total_marks = db.Column(
        db.Integer,
        nullable=False,
        default=0
    )

    status = db.Column(
        db.String(20),
        nullable=False,
        default="draft"
    )

    created_by = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc)
    )

    questions = db.relationship(
        "ExamQuestion",
        back_populates="exam",
        cascade="all, delete-orphan",
        order_by="ExamQuestion.position"
    )


# ==================================================
# EXAM QUESTION MODEL
# ==================================================

class ExamQuestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    exam_id = db.Column(
        db.Integer,
        db.ForeignKey("exam.id"),
        nullable=False
    )

    question_id = db.Column(
        db.Integer,
        db.ForeignKey("question.id"),
        nullable=False
    )

    position = db.Column(
        db.Integer,
        nullable=False,
        default=1
    )

    exam = db.relationship(
        "Exam",
        back_populates="questions"
    )

    question = db.relationship(
        "Question",
        lazy=True
    )

    __table_args__ = (
        db.UniqueConstraint(
            "exam_id",
            "question_id",
            name="unique_exam_question"
        ),
    )


# ==================================================
# STUDENT EXAM ATTEMPT MODEL
# ==================================================

class StudentAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    student_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    exam_id = db.Column(
        db.Integer,
        db.ForeignKey("exam.id"),
        nullable=False
    )

    started_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc)
    )

    submitted_at = db.Column(
        db.DateTime,
        nullable=True
    )

    score = db.Column(
        db.Float,
        nullable=True
    )

    status = db.Column(
        db.String(20),
        nullable=False,
        default="in_progress"
    )

    answers = db.relationship(
        "StudentAnswer",
        back_populates="attempt",
        cascade="all, delete-orphan"
    )

    student = db.relationship("User")
    exam = db.relationship("Exam")


# ==================================================
# STUDENT ANSWER MODEL
# ==================================================

class StudentAnswer(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    attempt_id = db.Column(
        db.Integer,
        db.ForeignKey("student_attempt.id"),
        nullable=False
    )

    question_id = db.Column(
        db.Integer,
        db.ForeignKey("question.id"),
        nullable=False
    )

    answer_text = db.Column(
        db.Text,
        nullable=True
    )

    marks_awarded = db.Column(
        db.Float,
        nullable=True
    )

    attempt = db.relationship(
        "StudentAttempt",
        back_populates="answers"
    )

    question = db.relationship("Question")

    __table_args__ = (
        db.UniqueConstraint(
            "attempt_id",
            "question_id",
            name="unique_attempt_question"
        ),
    )
