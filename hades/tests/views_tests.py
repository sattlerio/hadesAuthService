import app
import unittest
from config import TestingConfig
import json
from hades.models import *
from flask_jwt_extended import decode_token


class ViewsTestCase(unittest.TestCase):
    def setUp(self):
        app.app.testing = True
        self.app = app.app.test_client()
        app.app.config.from_object(TestingConfig)

        with app.app.app_context():
            app.db.init_app(app.app)
            app.db.create_all()

            company1 = Company(name="test1")
            user1 = User("Max", "Mustermann", "max@mustermann.com",
                         "d0nt4get",
                         False, False, False, [company1])

            app.db.session.add(company1)
            app.db.session.add(user1)
            app.db.session.commit()

    def test_ping_route(self):
        rv = self.app.get('/auth/ping')
        assert rv.status_code == 200
        assert b"pong" in rv.data

    def test_login_errors(self):
        # test empty body
        rv = self.app.post('/auth/login',
                           content_type='application/json')
        assert rv.status_code == 400
        data = json.loads(rv.data)
        assert data["status"] == "error"
        assert data["message"] == "please submit username and password"

        # test wrong content type
        rv = self.app.post('/auth/login',
                           content_type='text')
        assert rv.status_code == 400
        data = json.loads(rv.data)
        assert data["status"] == "error"
        assert data["message"] == "you have to set content type to json"

        # test unkown user
        rv = self.app.post('/auth/login',
                           data=json.dumps(dict(username='franz', password="tipsi")),
                           content_type='application/json')
        assert rv.status_code == 400
        data = json.loads(rv.data)
        assert data["status"] == "error"
        assert data["message"] == "unknown user"

        # test wrong password
        rv = self.app.post('/auth/login',
                           data=json.dumps(dict(username='max@mustermann.com', password="wrongPaswsowrd")),
                           content_type='application/json')
        assert rv.status_code == 401
        data = json.loads(rv.data)
        assert data["status"] == "error"
        assert data["message"] == "the submitted password is wrong"

    def test_successful_login(self):
        # test successfull user
        rv = self.app.post('/auth/login',
                           data=json.dumps(dict(username='max@mustermann.com', password="d0nt4get")),
                           content_type='application/json')
        assert rv.status_code == 200
        data = json.loads(rv.data)
        assert data["status"] == "OK"

        user = decode_token(data["access_token"])
        assert user["identity"]["firstname"] == "Max"
        assert user["identity"]["lastname"] == "Mustermann"

        access_token = data["access_token"]
        refresh_token = data["refresh_token"]


        # test refresh token
        rv = self.app.post("/auth/refresh",
                           content_type="application/json",
                           headers={
                               'Authorization': 'Bearer ' + refresh_token
                           })
        assert rv.status_code == 200
        data = json.loads(rv.data)
        assert "access_token" in data
        access_token = data["access_token"]

        # test successfull user
        rv = self.app.post('/auth/fresh-login',
                           data=json.dumps(dict(username='max@mustermann.com', password="d0nt4get")),
                           content_type='application/json')
        assert rv.status_code == 200
        data = json.loads(rv.data)
        assert data["status"] == "OK"

        user = decode_token(data["access_token"])
        assert user["identity"]["firstname"] == "Max"
        assert user["identity"]["lastname"] == "Mustermann"

        access_token = data["access_token"]

        # test refresh token
        rv = self.app.put("/auth/change-password",
                           content_type="application/json",
                          data=json.dumps(dict(password="newPassword")),
                           headers={
                               'Authorization': 'Bearer ' + access_token
                           })
        assert rv.status_code == 200

        # test refresh token
        rv = self.app.get("/auth/user",
                          content_type="application/json",
                          headers={
                              'Authorization': 'Bearer ' + access_token
                          })
        assert rv.status_code == 200
        data = json.loads(rv.data)
        assert data["status"] == "OK"
        assert data["user"]["email"] == "max@mustermann.com"

        rv = self.app.post('/auth/login',
                           data=json.dumps(dict(username='max@mustermann.com', password="d0nt4get")),
                           content_type='application/json')
        assert rv.status_code == 401
        data = json.loads(rv.data)
        assert data["status"] == "error"


    def tearDown(self):
        app.db.session.remove()
        app.db.drop_all()
