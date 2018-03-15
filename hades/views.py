from flask import jsonify, request, Blueprint, current_app as app
from hades.models import *
from flask_jwt_extended import (
    create_access_token, create_refresh_token,
    jwt_refresh_token_required, get_jwt_identity,
    jwt_required, fresh_jwt_required
)
import uuid

authentication = Blueprint('authentication', __name__)


@authentication.route('/ping', methods=['GET'])
def test():
    return "pong"


@authentication.route('/user')
@jwt_required
def fetch_user_information():
    tid = uuid.uuid4()
    app.logger.info(f"new request to fetch user identity - {tid}")

    current_user = get_jwt_identity()
    app.logger.info(f"{tid}: successfully validated user identity")

    user_query = User.query.filter_by(user_uuid=current_user["uuid"])
    if user_query.count() == 1:
        user = user_query.first()

        data = {
            "firstname": user.firstname,
            "lastname": user.lastname,
            "email": user.email,
            "user_id": user.user_uuid
        }

        return jsonify({
            "status": "OK",
            "request_id": tid,
            "user": data
        })

    return jsonify({
        "status": "error",
        "request_id": tid,
        "message": "unable to get user identity"
    }), 500


def _handle_regular_login(data, t_id, refresh=False):
    app.logger.info(f"{t_id}: handle default login with username and password")

    username = data.get("username", None)
    password = data.get("password", None)

    if not username or not password:
        app.logger.info(f"abort transaction {t_id} because of missing data")
        return jsonify({
            "status": "error",
            "request_id": t_id,
            "message": "please provide a value for username and password"
        }), 400

    user = User.query.filter_by(email=username)
    if user.count() != 1:
        app.logger.info(f"abort transaction {t_id}, because could not find user")
        return jsonify({
            "status": "error",
            "request_id": t_id,
            "message": "unknown user"
        }), 400

    user = user.first()
    if not user.check_password(password):
        app.logger.info(f"abort transaction {t_id}, because the password submitted is wrong")
        return jsonify({
            "status": "error",
            "request_id": t_id,
            "message": "the submitted password is wrong"
        }), 401

    identity = {
        "firstname": user.firstname,
        "lastname": user.lastname,
        "email": user.email,
        "uuid": user.user_uuid
    }
    access_token = create_access_token(identity=identity, fresh=True)
    app.logger.info(f"{t_id} successfully logged in user")

    data = {
        "status": "OK",
        "request_id": t_id,
        "access_token": access_token,
        "message": "successfully logged in - welcome"
    }
    if not refresh:
        token = create_refresh_token(identity=identity)
        data["refresh_token"] = token

    return jsonify(data), 200


@authentication.route("/login", methods=["POST"])
def login():
    t_id = str(uuid.uuid4())
    app.logger.info(f"new login transaction with id {t_id}")
    if not request.is_json:
        app.logger.info(f"abort transaction {t_id} because of wrong contentype")
        return jsonify({
            "status": "error",
            "request_id": t_id,
            "message": "you have to set content type to json"
        }), 400

    if not request.data:
        app.logger.info(f"abort transaction {t_id} because of missing header")
        return jsonify({
            "status": "error",
            "request_id": t_id,
            "message": "please submit username and password"
        }), 400

    data = request.get_json()
    return _handle_regular_login(data, t_id)


@authentication.route("/fresh-login", methods=["POST"])
def fresh_login():
    t_id = str(uuid.uuid4())
    app.logger.info(f"new login transaction with id {t_id}")
    if not request.is_json:
        app.logger.info(f"abort transaction {t_id} because of wrong contentype")
        return jsonify({
            "status": "error",
            "request_id": t_id,
            "message": "you have to set content type to json"
        }), 400

    if not request.data:
        app.logger.info(f"abort transaction {t_id} because of missing header")
        return jsonify({
            "status": "error",
            "request_id": t_id,
            "message": "please submit username and password"
        }), 400

    data = request.get_json()
    return _handle_regular_login(data, t_id, refresh=True)


@authentication.route('/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh_token():
    tid = uuid.uuid4()
    app.logger.info(f"got new request to refresh token with id {tid}")
    current_user = get_jwt_identity()
    app.logger.info(f"{tid}: successfully validated jwt")

    if User.query.filter_by(user_uuid=current_user["uuid"]).count() == 1:
        ret = {
            'access_token': create_access_token(identity=current_user, fresh=False),
            "status": "OK",
            "message": "successfully refreshed access token",
            "request_id": tid
        }
        return jsonify(ret), 200
    else:
        return jsonify({
            "status": "error",
            "request_id": tid,
            "message": "user doesnt exist"
        }), 400


@authentication.route('/change-password', methods=['PUT'])
@fresh_jwt_required
def change_password():
    tid = uuid.uuid4()
    app.logger.info(f"got new request to change password {tid}")

    if not request.is_json:
        app.logger.info(f"abort transaction {t_id} because of wrong contentype")
        return jsonify({
            "status": "error",
            "request_id": tid,
            "message": "you have to set content type to json"
        }), 400

    current_user = get_jwt_identity()

    password = request.get_json().get('password', None)

    if not password:
        app.logger.info(f"abort transaction {tid} because of missing data")
        return jsonify({
            "status": "error",
            "request_id": tid,
            "message": f"you have to submit the new password"
        })

    if User.query.filter_by(user_uuid=current_user["uuid"]).count() != 1:
        app.logger.info(f"abort transaction {tid} because user does not exist")
        return jsonify({
            "status": "error",
            "request_id": tid,
            "message": "user doesnt exist"
        }), 400

    user = User.query.filter_by(user_uuid=current_user["uuid"]).first()
    user._set_password(password)

    app.logger.info(f"{tid} successfully changed password")
    return jsonify({
        "status": "OK",
        "request_id": tid,
        "message": "successfully changed password"
    })
