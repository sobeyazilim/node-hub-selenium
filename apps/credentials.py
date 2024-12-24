# primary libraries
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Response, Form, Depends, HTTPException, File, Path, UploadFile

from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from core.services.serviceLogger import service_logger, service_logger_debug
import json
from starlette.middleware.sessions import SessionMiddleware
import sys
from pydantic import BaseModel, ValidationError
from sqlalchemy.exc import DBAPIError
from uuid import uuid4
from typing import Optional
import os
from user_agents import parse

# class
from core.classes.class_credentials import class_credentials
from core.classes.class_administration import class_administration
from core.classes.class_base import class_base
from core.models.Pydantic.form_credentials import  *
from core.models.SQLAlchemy.credentials import ModelCredentials
from core.classes.class_configuration import class_configuration

# services
from core.services.serviceLogger import service_logger
from core.providers.dbprovider import dbprovider

 #models
from core.models.Pydantic.internal import pydantic_request_login_auth 

credentials = FastAPI(
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

templates = Jinja2Templates(directory="templates")

@credentials.get("", dependencies=[Depends(class_base().token_dependency_check)])
@credentials.get("/", dependencies=[Depends(class_base().token_dependency_check)])
async def render_credentials(request: Request):    
    try:
        token = request.cookies.get(class_configuration().return_app_jwt_token_label())

        if token:
            # get public id
            login_public_id = class_base().return_auth_token_public_id(token)

            # get full configuration
            full_configuration = class_configuration().return_configuration_full()

            # get users in same team
            usermanagement_users = class_administration().return_administration_usermanagement_users_in_same_team_by_public_id(login_public_id)

            # toastr
            success_message = request.session.pop("success_message", None)
            error_message = request.session.pop("error_message", None)
            warning_message = request.session.pop("warning_message", None)

            # offcanvas show
            show_offcanvas = request.session.pop("show_offcanvas", None)

            if "credentials_active_tab" not in request.session:
                request.session["credentials_active_tab"] = "insights"
                credentials_active_tab  = "insights"
            else:
                credentials_active_tab = request.session.pop("credentials_active_tab")

            if "credentials_content_tab" in request.session:
                credentials_content_tab = request.session.pop("credentials_content_tab")
            else:
                credentials_content_tab = None

            # clear edited object if exits
            if "edited_credentials_object" in request.session and request.session["edited_credentials_object"]:
                request.session["edited_credentials_object"] = None

            # get current user role and name
            current_user_role = class_administration().return_user_role_by_public_id(login_public_id)
            current_user = class_administration().return_login_name_by_public_id(login_public_id)

            # render page
            return templates.TemplateResponse(
                "index.html",
                {
                    "request": request,
                    "page_mode": 'default',
                    "build_number": class_configuration().return_app_build_number(), 
                    "current_user": current_user,
                    "current_user_role": current_user_role,
                    "select2_timezones": class_configuration().return_system_timezones(),
                    "full_configuration": full_configuration,
                    "usermanagement_users": usermanagement_users,
                    "success_message": success_message,
                    "error_message": error_message,
                    "warning_message": warning_message,
                    "show_offcanvas": show_offcanvas,
                    "credentials_active_tab": credentials_active_tab,
                    "credentials_content_tab": credentials_content_tab,
                }
            )
        
        request.session["warning_message"] = "You must log in to access"
        return RedirectResponse(url="/login", status_code=302)
    
    except Exception as e:
        service_logger().error(f"Error handling credentials page: {e}")
        return RedirectResponse(url="/login", status_code=302) 


@credentials.get("/credentials/create", dependencies=[Depends(class_base().token_dependency_check)])
async def credentials_create_new(request: Request, tabname: str = Path(...), contentmenu: Optional[str] = None):    
    try:
        token = request.cookies.get(class_configuration().return_app_jwt_token_label())

        if token:
            # get public id
            login_public_id = class_base().return_auth_token_public_id(token)

            # get full configuration
            full_configuration = class_configuration().return_configuration_full()
            
            # get users in same team
            usermanagement_users = class_administration().return_administration_usermanagement_users_in_same_team_by_public_id(login_public_id)


            # toastr
            success_message = request.session.pop("success_message", None)
            error_message = request.session.pop("error_message", None)
            warning_message = request.session.pop("warning_message", None)

            # offcanvas show
            show_offcanvas = request.session.pop("show_offcanvas", None)
            

            request.session["credentials_active_tab"] = tabname
            credentials_active_tab = tabname
            
            if 'credentials_content_tab' not in request.session:
                request.session["credentials_content_tab"] = contentmenu
                credentials_content_tab = contentmenu
            else:
                credentials_content_tab = request.session["credentials_content_tab"]
                
            
            current_user_role = class_administration().return_user_role_by_public_id(login_public_id)
            current_user = class_administration().return_login_name_by_public_id(login_public_id)
            
            # clear edited object if exits§
            if "edited_credentials_object" in request.session and request.session["edited_credentials_object"]:
                request.session["edited_credentials_object"] = None

            # render page
            return templates.TemplateResponse(
                "credentials.html",
                {
                    "request": request,
                    "page_mode": 'create',
                    "build_number": class_configuration().return_app_build_number(), 
                    "current_user": current_user,
                    "current_user_role": current_user_role,
                    "select2_timezones": class_configuration().return_system_timezones(),
                    "full_configuration": full_configuration,
                    "usermanagement_users": usermanagement_users,
                    "success_message": success_message,
                    "error_message": error_message,
                    "warning_message": warning_message,
                    "show_offcanvas": show_offcanvas,
                    "credentials_active_tab": credentials_active_tab,
                    "credentials_content_tab": credentials_content_tab,
                }
            )

        request.session["warning_message"] = "You must log in to access"
        return RedirectResponse(url="/login", status_code=302)
    
    except Exception as e:
        service_logger().error(f"Error handling credentials page: {e}")
        return RedirectResponse(url="/credentials", status_code=302)
    
@credentials.get("/{tabname}/edit", dependencies=[Depends(class_base().token_dependency_check)])
@credentials.get("/{tabname}/{contentmenu}/edit", dependencies=[Depends(class_base().token_dependency_check)])
async def credentials_edit_object(request: Request, tabname: str = Path(...), contentmenu: Optional[str] = None):
    try:
        token = request.cookies.get(class_configuration().return_app_jwt_token_label())
        service_logger().debug(f"Token: {token}")

        if token:
            # get public id
            login_public_id = class_base().return_auth_token_public_id(token)
            service_logger().debug(f"Login Public ID: {login_public_id}")

            # get full configuration
            full_configuration = class_configuration().return_configuration_full()
            service_logger().debug(f"Full Configuration: {full_configuration}")

            # get users in same team
            usermanagement_users = class_administration().return_administration_usermanagement_users_in_same_team_by_public_id(login_public_id)
            service_logger().debug(f"User Management Users: {usermanagement_users}")


            # toastr
            success_message = request.session.pop("success_message", None)
            error_message = request.session.pop("error_message", None)
            warning_message = request.session.pop("warning_message", None)
            service_logger().debug(f"Success Message: {success_message}, Error Message: {error_message}, Warning Message: {warning_message}")

            # offcanvas show
            show_offcanvas = request.session.pop("show_offcanvas", None)
            service_logger().debug(f"Show Offcanvas: {show_offcanvas}")

            request.session["credentials_active_tab"] = tabname
            credentials_active_tab = tabname
            service_logger().debug(f"credentials Active Tab: {credentials_active_tab}")

            if 'credentials_content_tab' not in request.session:
                request.session["credentials_content_tab"] = contentmenu
                credentials_content_tab = contentmenu
            else:
                credentials_content_tab = request.session["credentials_content_tab"]
            service_logger().debug(f"credentials Content Tab: {credentials_content_tab}")

            # check edited object
            if "edited_credentials_object" in request.session and request.session["edited_credentials_object"]:
                edited_credentials_object = request.session["edited_credentials_object"]
            else:
                service_logger().error(f"No credentials found to edit")
                return RedirectResponse(url="/credentials/", status_code=302)
            service_logger().debug(f"Edited credentials Object: {edited_credentials_object}")


            current_user_role = class_administration().return_user_role_by_public_id(login_public_id)
            current_user = class_administration().return_login_name_by_public_id(login_public_id)
            service_logger().debug(f"Current User Role: {current_user_role}, Current User: {current_user}")

            # clear edited object if exits
            if "edited_credentials_object" in request.session and request.session["edited_credentials_object"]:
                request.session["edited_credentials_object"] = None
            else:
                service_logger().error(f"No credentials found to edit")
                return RedirectResponse(url="/credentials/", status_code=302)
            service_logger().debug(f"Cleared Edited credentials Object")

            if current_user_role == 'readonly':
                tickets = [ticket for ticket in tickets if ticket['assignee_name'] == current_user]
                service_logger().debug(f"Filtered Tickets for Readonly User: {tickets}")

            # filter tickets and users if user role is teamadmin
            elif current_user_role == 'teamadmin':
                team_members = [user['username'] for user in users if user['team'] == current_user_role]
                tickets = [ticket for ticket in tickets if ticket['assignee_name'] in team_members]
                users = [user for user in users if user['username'] in team_members]
                service_logger().debug(f"Filtered Tickets and Users for Teamadmin: {tickets}, {users}")

            # render page
            return templates.TemplateResponse(
                "credentials.html",
                {
                    "request": request,
                    "page_mode": 'edit',
                    "build_number": class_configuration().return_app_build_number(), 
                    "current_user": current_user,
                    "current_user_role": current_user_role,
                    "edited_credentials_object": edited_credentials_object,
                    "select2_timezones": class_configuration().return_system_timezones(),
                    "full_configuration": full_configuration,
                    "usermanagement_users": usermanagement_users,
                    "success_message": success_message or "",
                    "error_message": error_message or "",
                    "warning_message": warning_message or "",
                    "show_offcanvas": show_offcanvas or "",
                    "credentials_active_tab": credentials_active_tab,
                    "credentials_content_tab": credentials_content_tab or "",

                }
            )
        
        request.session["warning_message"] = "You must log in to access"
        return RedirectResponse(url="/login", status_code=302)
    
    except Exception as e:
        service_logger().error(f"Error handling credentials page: {e}")
        return RedirectResponse(url="/credentials", status_code=302)



@credentials.post("/tickets/edit/{public_id}", dependencies=[Depends(class_base().token_dependency_check)])
async def credentials_ticket_edit(request: Request, public_id: str = Path(...)):
    try:
        token = request.cookies.get(class_configuration().return_app_jwt_token_label())

        if token:
            # get public id
            login_public_id = class_base().return_auth_token_public_id(token)

            if class_administration().return_user_role_by_public_id(login_public_id) == 'read-only':
                # Set warning message in session
                request.session["warning_message"] = "Unauthorised access"
                return RedirectResponse(url="/index", status_code=302)
            
            # check ticket whether if it exists
            edited_credentials_object = class_credentials().return_ticket_by_public_id(public_id)
            service_logger().debug(f"Edited credentials Object: {edited_credentials_object}")
            if edited_credentials_object:
                request.session["edited_credentials_object"] = edited_credentials_object
            else:
                request.session["warning_message"] = "Ticket not found"
                return RedirectResponse(url="/credentials/", status_code=302)
        else:
            request.session["warning_message"] = "You must log in to access"
            return RedirectResponse(url="/login", status_code=302)
        
    except Exception as error:
        service_logger().error(f"Unexpected error handling ticket edit form: {error}")
        request.session["warning_message"] = "Unexpected error occurred. Please check logs."
  
    finally:
        request.session["credentials_active_tab"] = "tickets"
        return RedirectResponse(url="/credentials/tickets/edit/", status_code=302)


# @credentials.post("/tickets/delete/{public_id}", dependencies=[Depends(class_base().token_dependency_check)])
# async def credentials_ticket_delete(request: Request, public_id: str = Path(...)):
#     try:
#         token = request.cookies.get(class_configuration().return_app_jwt_token_label())

#         if token:
#             # get public id
#             login_public_id = class_base().return_auth_token_public_id(token)

#             if class_administration().return_user_role_by_public_id(login_public_id) == 'read-only':
#                 # Set warning message in session
#                 request.session["warning_message"] = "Unauthorised access"
#                 return RedirectResponse(url="/index", status_code=302)
            
#         # delete ticket
#         if class_credentials().delete_ticket_by_public_id(public_id):
#             request.session["success_message"] = "Successfully deleted"
#         else:
#             request.session["error_message"] = "Delete failed. Please check logs."

#     except Exception as error:
#         service_logger().error(f"Unexpected error handling ticket delete form: {error}")
#         request.session["warning_message"] = "Unexpected error occurred. Please check logs."
  
#     finally:
#         request.session["credentials_active_tab"] = "tickets"
#         return RedirectResponse(url="/credentials/", status_code=302)
