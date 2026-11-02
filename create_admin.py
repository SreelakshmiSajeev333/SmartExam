from getpass import getpass

from app import app
from models import db, User


def create_admin():
    print("\n===== SmartExam Admin Account Setup =====\n")

    name = input("Enter admin name: ").strip()
    email = input("Enter admin email: ").strip().lower()
    password = getpass("Create admin password: ")
    confirm_password = getpass("Confirm admin password: ")

    if not name or not email or not password:
        print("Error: All fields are required.")
        return

    if password != confirm_password:
        print("Error: Passwords do not match.")
        return

    if len(password) < 8:
        print("Error: Password must contain at least 8 characters.")
        return

    with app.app_context():
        existing_user = User.query.filter_by(email=email).first()

        if existing_user:
            print("Error: This email is already registered.")
            print("Use a different email address for the admin account.")
            return

        admin = User(
            name=name,
            email=email,
            role="admin"
        )

        admin.set_password(password)

        db.session.add(admin)
        db.session.commit()

        print("\nSUCCESS! Admin account created.")
        print("Email:", email)
        print("Role: admin")
        print("\nYou can now log in to SmartExam.")


if __name__ == "__main__":
    create_admin()