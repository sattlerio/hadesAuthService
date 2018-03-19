from flask import jsonify, request, Blueprint, Response, current_app as app
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


@authentication.route('/fetch/user_companies')
@jwt_required
def fetch_user_companies():
    tid = uuid.uuid4()
    app.logger.info(f"{tid}: new request to fetch user companies")

    current_user = get_jwt_identity()
    app.logger.info(f"{tid}: validated user identity")

    user = User.query.filter_by(user_uuid=current_user["uuid"]).first_or_404()

    single_company = False
    if len(user.companies) == 1:
        single_company = True

    companies = []
    for company in user.companies:
        companies.append({
            "name": company.name,
            "company_id": company.company_uuid
        })

    data = {
        "status": "OK",
        "request_id": tid,
        "companies": companies,
        "single_company": single_company
    }
    return jsonify(data)


@authentication.route('/validate/user_company/<company_id>', methods=["GET"])
@jwt_required
def validate_user_company(company_id):
    tid = uuid.uuid4()
    app.logger.info(f"{tid}: new request to validate user company permissions")

    current_user = get_jwt_identity()
    app.logger.info(f"{tid}: validated user identity")

    query = User.query.filter(User.companies.any(company_uuid=company_id)).filter_by(user_uuid=current_user["uuid"])
    if query.count() == 1:
        app.logger.info(f"{tid}: user is allowed to access resource")
        return jsonify(status="OK",
                       message="User is allowed to access company",
                       request_id=tid), 200
    else:
        u = User.query.filter_by(user_uuid=current_user["uuid"]).first_or_404()
        app.logger.info(f"{tid}: user is not allowed to access resource, check single or multi user")
        if len(u.companies) == 1:
            app.logger.info(f"{tid}: abort transaction - user is single merchant")
            return jsonify(
                status="ERROR",
                message="Company does not exist",
                request_id=tid,
                single_company=True,
                company=u.companies[0].company_uuid
            ), 400
        else:
            app.logger.info(f"{tid}: abort transaction - user is multi merchant")
            return jsonify(
                status="ERROR",
                message="Company does not exist",
                request_id=tid,
                single_company=False
            ), 400


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

        companies = []
        for company in user.companies:
            companies.append({
                "company_uuid": company.company_uuid,
                "company_name": company.name
            })

        data = {
            "firstname": user.firstname,
            "lastname": user.lastname,
            "email": user.email,
            "user_id": user.user_uuid,
            "companies": companies
        }

        return jsonify({
            "status": "OK",
            "request_id": tid,
            "data": data
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


@authentication.route("/user", methods=["POST"])
@jwt_required
def change_user():
    t_id = str(uuid.uuid4())
    current_user = get_jwt_identity()
    app.logger.info(f"new adapt user transaction {t_id}")
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
            "message": "please submit data"
        }), 400

    data = request.get_json()
    if User.query.filter_by(user_uuid=current_user["uuid"]).count() == 1:
        user = User.query.filter_by(user_uuid=current_user["uuid"]).first()

        firstname = data.get("firstname", None)
        lastname = data.get("lastname", None)
        email = data.get("email", None)

        if firstname:
            user.firstname = data["firstname"]
        if lastname:
            user.lastname = data["lastname"]
        if email:
            user.email = data["email"]

    db.session.add(user)
    db.session.commit()

    return jsonify(request_id=t_id,
                   status="OK",
                   message="Successfully updated user")




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


@authentication.route("/refresh")
@jwt_required
def renew_fresh_token():
    tid = uuid.uuid4()
    app.logger.info(f"got new request to refresh token: {tid}")
    current_user = get_jwt_identity()

    if User.query.filter_by(user_uuid=current_user["uuid"]).count() == 1:
        new_token = create_access_token(identity=current_user, fresh=False)
        resp = Response(jsonify({
            'access_token': new_token,
            "status": "OK",
            "message": "successfully refreshed access token",
            "request_id": tid
        }))
        resp.headers["Authorization"] = new_token

        return resp, 200
    else:
        return jsonify({
            "status": "error",
            "request_id": tid,
            "message": "user is not allowed to access"
        }), 401


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
