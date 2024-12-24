# primary libraries
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Response, Form, Depends, HTTPException, Query, BackgroundTasks
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

# class
from core.classes.class_configuration import class_configuration
from core.classes.class_administration import class_administration
from core.classes.class_base import class_base

# services
from core.services.serviceLogger import service_logger, service_logger_debug

account = FastAPI(
    title = class_configuration().return_app_title(),
    description = class_configuration().return_app_description(),
    summary = class_configuration().return_app_summary(),
    version = class_configuration().return_app_version(),
    terms_of_service = class_configuration().return_app_terms_of_service(),
    contact={
        "name": class_configuration().return_app_contact_name(),
        "email": class_configuration().return_app_contact_email(),
    },
    license_info={
        "name": class_configuration().return_app_company(),
        "url": class_configuration().return_app_terms_of_service(),
    },
    swagger_ui_parameters = {"syntaxHighlight.theme": "obsidian"},
    openapi_url = None,
    # docs_url = None,
    # redoc_url = None,
)

# Set up Jinja2 templates
templates = Jinja2Templates(directory="templates")

@account.post("/auth")
async def auth(request: Request, login_name: str = Form(...), login_password: str = Form(...)):
    try:
        if login_name and login_password:
            if class_administration().authenticate_user(login_name, login_password, request.client.host):
                public_id = class_administration().return_public_id_by_login_name(login_name)
                token = class_base().generate_auth_token(public_id)                
                request.session["success_message"] = "Successfully logged in"
                response = RedirectResponse(url="/index", status_code=302)
                response.set_cookie(key=class_configuration().return_app_jwt_token_label(), value=token)
                return response
        request.session["error_message"] = "Login failed. Invalid credentials!"
        return RedirectResponse(url="/login", status_code=302)
    
    except Exception as e:
        service_logger().error(f"Error authenticating user: {e}")
        request.session["error_message"] = "Login failed. Internal error!"
        return RedirectResponse(url="/login", status_code=302)


@account.post("/reset-password", dependencies=[Depends(class_base().token_dependency_check)])
async def reset_password(request: Request, current_password: str = Form(...),new_password: str = Form(...),confirm_password: str = Form(...),):
    try:
        # Validate that new_password and confirm_password match
        if new_password != confirm_password:
            request.session["error_message"] = "New passwords do not match"
            return RedirectResponse(url="/index", status_code=302)
        
        # get token from cookie
        token = request.cookies.get(class_configuration().return_app_jwt_token_label())

        # verify token
        if token:
            
            # get public id
            public_id = class_base().return_auth_token_public_id(token)

            if class_administration().return_login_name_by_public_id(public_id) == "master" or class_administration().return_user_type_by_public_id(public_id) != "local":
                request.session["error_message"] = "Restricted operation for desired user's type"
                return RedirectResponse(url="/index", status_code=302)

            # check cannot change password enabled
            if not class_administration().verify_can_change_password(public_id):
                request.session["error_message"] = "Password change restricted for user"
                return RedirectResponse(url="/index", status_code=302)
            
            # verify old password
            if not class_administration().verify_old_password_by_public_id(public_id, current_password):
                request.session["error_message"] = "Old password not correct"
                return RedirectResponse(url="/index", status_code=302)
            
            # reset password
            if class_administration().reset_password_by_public_id(public_id, new_password):

                # redirect success message
                request.session["success_message"] = "Password has been successfully reset"
                return RedirectResponse(url="/index", status_code=302)
            
            else:
                # redirect error message
                request.session["error_message"] = "Error occured while resetting password"
                return RedirectResponse(url="/index", status_code=302)
            

        request.session["warning_message"] = "You must log in to access"
        return RedirectResponse(url="/login", status_code=302)
    
    except Exception as e:
        service_logger().error(f"Error handling reset password page: {e}")
        return RedirectResponse(url="/login", status_code=302)

