# Interrival – Authentication Module
HTML · CSS · JavaScript · Bootstrap 5 · Python (Flask, single `app.py`) · MySQL

## Structure
```
app.py                 all backend (routes, DB, security, seed command)
schema.sql             MySQL tables
.env.example           copy to .env
templates/             base_auth, _components, login, forgot_password, reset_password,
                       contact_admin, error, admin_dashboard, employee_dashboard
static/                auth.css, auth.js, images/
```

## Run
```bash
pip install -r requirements.txt
copy .env.example .env        # (cp on Mac/Linux) then set SECRET_KEY and DB_PASSWORD
mysql -u root -p < schema.sql
python app.py seed            # demo users
python app.py                 # http://127.0.0.1:5000
```
Demo: `admin@interrival.com / Admin@123`, `rahul@interrival.com / Employee@123`.
Without SMTP settings, password-reset links are printed in the terminal.
