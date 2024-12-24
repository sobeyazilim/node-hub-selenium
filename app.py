# Copyright SOBE YAZILIM.  See LICENSE file for details.
# @@@Author : Murat BÜLBÜL
# @@@Email  : murat.bulbul@sobeyazilim.com.tr

# primary libraries
from fastapi import FastAPI, Path, Request, Depends
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from apscheduler.schedulers.background import BackgroundScheduler
import uvicorn
import os
import json


# providers
from core.providers.dbprovider import initialize_db
from core.providers.scheduler import scheduled_task

# class
from core.classes.class_configuration import class_configuration
from core.classes.class_administration import class_administration
from core.classes.class_base import class_base

# services
from core.services.serviceLogger import service_logger

# sub apps import
from apps.account import account

app = FastAPI(
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
    docs_url = "/api/tester",
    redoc_url = None
)

# add session middleware
app.add_middleware(SessionMiddleware, secret_key=class_configuration().return_app_secret_key())


# add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust as necessary for your use case
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# mount sub applications
app.mount("/static", StaticFiles(directory="static"), name="static")
app.mount("/account", account)

# Set up Jinja2 templates
templates = Jinja2Templates(directory="templates")

# create a scheduler instance for dbprovider table partition, sizing and old tables dropping
scheduler = BackgroundScheduler()
scheduler.add_job(scheduled_task, 'cron', hour=00, minute=30)  # Run daily at 00:00 AM

# Fast api new version
# @app.lifespan()
# async def lifespan(app: FastAPI) -> AsyncIterator[None]:
#     # Initialize the database
#     initialize_db()
#     service_logger().info("Database initialized.")

#     # Start the scheduler when the application starts
#     scheduler.start()
#     service_logger().info("Scheduler started.")

#     # Yield control back to FastAPI
#     yield

#     # Shutdown the scheduler when the application shuts down
#     scheduler.shutdown()
#     service_logger().info("Scheduler stopped.")

@app.on_event("startup")
async def on_startup():
    """Event handler for application startup."""
    try:
        # Initialize the database
        initialize_db()
        service_logger().info("Database initialized.")
        
        # Start the scheduler
        scheduler.start()
        service_logger().info("Scheduler started.")
    
    except Exception as error:
        service_logger().error(f"Startup task error: {error}")

@app.on_event("shutdown")
async def on_shutdown():
    # Shutdown the scheduler when the application shuts down
    try:
        scheduler.shutdown()
        service_logger().info("Scheduler stopped.")
        
    except Exception as error:
        service_logger().error(f"Startup task error: {error}")

@app.get("/", dependencies=[Depends(class_base().token_dependency_check)])
async def render_index(request: Request):
    # redirect to login page
    return RedirectResponse(url="/index", status_code=302)

@app.get("/login")
async def login_form(request: Request):
    try:
        token = request.cookies.get(class_configuration().return_app_jwt_token_label())

        if token and class_base().verify_auth_token(request, token):
            return RedirectResponse(url="/index", status_code=302)
        
        # messages
        success_message = request.session.pop("success_message", None)
        error_message = request.session.pop("error_message", None)
        warning_message = request.session.pop("warning_message", None)
        
        return templates.TemplateResponse(
            "login.html", 
            {
                "request": request, 
                "build_number": class_configuration().return_app_build_number(),
                "success_message": success_message, 
                "error_message": error_message, 
                "warning_message": warning_message
            }
        )
    except Exception as e:
        service_logger().error(f"Error handling login form: {e}")
        return RedirectResponse(url="/login", status_code=302)
    
@app.get("/logout", dependencies=[Depends(class_base().token_dependency_check)])
async def logout(request: Request):

    # Set warning message in session
    request.session["success_message"] = "Logged out"

    # redirect to login page
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie(key=class_configuration().return_app_jwt_token_label())
    return response

@app.get("/index", dependencies=[Depends(class_base().token_dependency_check)])
async def index(request: Request):
    try:
        token = request.cookies.get(class_configuration().return_app_jwt_token_label())

        if token:
            # get public id
            public_id = class_base().return_auth_token_public_id(token)
            
            # get list of bookmarks
            
            # get list of groups
            
            # get list of credentials
            
            # get list of permissions
            _permissions = [{'public_id':'pb_111', 'name': 'name1', 'api': '1234'}, {'public_id':'pb_222', 'name': 'name2', 'api': '5555'}]
            
            # define default landing page
            if "active_tab" not in request.session:
                request.session["active_tab"] = "bookmarks"
                active_tab  = "bookmarks"
            else:
                active_tab = request.session.pop("active_tab")
            # toastr
            success_message = request.session.pop("success_message", None)
            error_message = request.session.pop("error_message", None)
            warning_message = request.session.pop("warning_message", None)
            print('active', active_tab)
            return templates.TemplateResponse(
                "index.html", 
                {
                    "request": request, 
                    "build_number": class_configuration().return_app_build_number(), 
                    "current_user": class_administration().return_login_name_by_public_id(public_id),
                    "current_user_role": class_administration().return_user_role_by_public_id(public_id),
                    "success_message": success_message, 
                    "error_message": error_message, 
                    "warning_message": warning_message,
                    "active_tab": active_tab,
                    "permissions": _permissions
                }
            )
        request.session["warning_message"] = "You must log in to access"
        return RedirectResponse(url="/login", status_code=302)
    
    except Exception as e:
        service_logger().error(f"Error handling index page: {e}")
        return RedirectResponse(url="/login", status_code=302)
    
@app.get("/user", dependencies=[Depends(class_base().token_dependency_check)])
async def user(request: Request):
    try:
        token = request.cookies.get(class_configuration().return_app_jwt_token_label())

        if token:
            # get public id
            public_id = class_base().return_auth_token_public_id(token)

            with open('bookmark_data.json', 'r', encoding='utf-8') as data:
                bookmark_data = json.load(data)

            with open('group_data.json', 'r', encoding='utf-8') as data:
                group_data = json.load(data)

            # toastr
            success_message = request.session.pop("success_message", None)
            error_message = request.session.pop("error_message", None)
            warning_message = request.session.pop("warning_message", None)

            return templates.TemplateResponse(
                "user_index.html", 
                {
                    "request": request, 
                    "build_number": class_configuration().return_app_build_number(), 
                    "current_user": class_administration().return_login_name_by_public_id(public_id),
                    "current_user_role": class_administration().return_user_role_by_public_id(public_id),
                    "bookmark_data": bookmark_data, 
                    "group_data": group_data, 
                    "success_message": success_message, 
                    "error_message": error_message, 
                    "warning_message": warning_message
                }
            )
        request.session["warning_message"] = "You must log in to access"
        return RedirectResponse(url="/login", status_code=302)
    
    except Exception as e:
        service_logger().error(f"Error handling index page: {e}")
        return RedirectResponse(url="/login", status_code=302)
    

@app.get("/{tabname}/create", dependencies=[Depends(class_base().token_dependency_check)])
async def create_forms(request: Request, tabname: str = Path(...)):    
    try:
        token = request.cookies.get(class_configuration().return_app_jwt_token_label())

        if token:
            # get public id
            login_public_id = class_base().return_auth_token_public_id(token)

            if class_administration().return_user_role_by_public_id(login_public_id) != 'superadmin':
                # Set warning message in session
                request.session["warning_message"] = "Unauthorised access"
                return RedirectResponse(url="/index", status_code=302)

            # toastr
            success_message = request.session.pop("success_message", None)
            error_message = request.session.pop("error_message", None)
            warning_message = request.session.pop("warning_message", None)
            
            request.session["active_tab"] = tabname
            
            # clear edited object if exits
            if "edited_object" in request.session and request.session["edited_object"]:
                request.session["edited_object"] = None
                
            # Data content to be passed to tml
            context = {
                "request": request,
                "page_mode" : 'create',
                "build_number": class_configuration().return_app_build_number(),
                "current_user": class_administration().return_login_name_by_public_id(login_public_id),
                "current_user_role": class_administration().return_user_role_by_public_id(login_public_id),
                "select2_timezones": class_configuration().return_system_timezones(),
                "success_message": success_message,
                "error_message": error_message,
                "warning_message": warning_message,
                "active_tab" : tabname
            }
            # Dynamic render context according to tabname
            match tabname:
                case 'bookmarks':
                    context['bookmarks'] = [] # get neccessary data for create form
                case 'groups':
                    context['groups'] = [] # get neccessary data for create form
                case 'credentials':
                    context['credentials'] = [] # get neccessary data for create form
                case 'permissions':
                    context['permissions'] = [] # get neccessary data for create form

            # render page
            return templates.TemplateResponse(
                "index.html",
                context
            )
        
        request.session["warning_message"] = "You must log in to access"
        return RedirectResponse(url="/login", status_code=302)
    
    except Exception as e:
        service_logger().error(f"Error handling get create orchestration page: {e}")
        return RedirectResponse(url="/login", status_code=302)

if __name__ == "__main__":

    print(class_configuration().return_app_title())
    print(class_configuration().return_app_description())

    # Determine the number of workers based on CPU cores
    num_workers = os.cpu_count() or 1  # Use 1 worker if cpu_count() returns None

    # Start application with uvicorn
    uvicorn.run(
        "app:app",  # Replace with your module name and app instance
        host="0.0.0.0",
        port=9876,
        reload=class_configuration().return_app_debug_mode(), # Enables auto-reloading
        workers=num_workers,  # Use the number of CPU cores for workers
        ssl_keyfile="core/certs/key.pem",
        ssl_certfile="core/certs/cert.pem"
    )