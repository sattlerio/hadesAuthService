from app import db
from werkzeug.security import generate_password_hash, \
    check_password_hash
import uuid

rel_user2company = db.Table('rel_user2company',
                            db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
                            db.Column('company_id', db.Integer, db.ForeignKey('companies.id'), primary_key=True)
                            )


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    user_uuid = db.Column(db.String(250), unique=True, nullable=False)
    firstname = db.Column(db.String(250), nullable=False)
    lastname = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)

    employee = db.Column(db.Boolean, nullable=False, default=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)
    service_agent = db.Column(db.Boolean, nullable=False, default=False)

    companies = db.relationship('Company', secondary=rel_user2company, lazy='subquery',
                                backref=db.backref('users', lazy=True))

    def __init__(self, firstname, lastname, email, password, employee=False, admin=False, service_agent=False, companies=None):
        uid = uuid.uuid4().hex
        self.user_uuid = uid
        self.firstname = firstname
        self.lastname = lastname
        self.email = email
        self._set_password(password)
        self.employee = employee
        self.admin = admin
        self.service_agent = service_agent
        if companies:
            if type(companies) == list:
                for company in companies:
                    self.companies.append(company)
            else:
                self.companies.append(companies)

    def _set_password(self, password):
        self.password = generate_password_hash(password, salt_length=12)

    def check_password(self, password):
        return check_password_hash(self.password, password)


class Company(db.Model):
    __tablename__ = "companies"

    id = db.Column(db.Integer, primary_key=True)
    company_uuid = db.Column(db.String(250), unique=True, nullable=False)
    name = db.Column(db.String(250), nullable=False)

    def __init__(self, name):
        uuid = self._get_company_uuid()
        self.company_uuid = uuid
        self.name = name

    def _get_company_uuid(self):
        num = Company.query.count() + 1
        prefix = f"{num:06}"
        company_id = f"VC_{prefix}"
        return company_id