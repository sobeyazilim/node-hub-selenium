# primary libraries
from ldap3 import Server, ServerPool, Connection, Tls, set_config_parameter, get_config_parameter
from ldap3 import ALL, ALL_ATTRIBUTES, SUBTREE, NTLM, NONE, FIRST, SIMPLE, REUSABLE, ASYNC, ROUND_ROBIN, HASHED_SALTED_SHA, MODIFY_REPLACE, RESTARTABLE, RANDOM
from ldap3.utils.hashed import hashed
from ldap3.core.exceptions import *
from ldap3.core.exceptions import LDAPSocketOpenError, LDAPStartTLSError, LDAPInvalidCredentialsResult
from ldap3.extend.microsoft.addMembersToGroups import ad_add_members_to_groups as addUsersInGroups
from fastapi import HTTPException
import ssl

# providers
from core.providers.dbprovider import dbprovider

# class
from core.classes.class_configuration import class_configuration

# models
from core.models.SQLAlchemy.administration.ModelAdministrationUserManagementDirectoryConnector import ModelAdministrationUserManagementDirectoryConnector
from core.models.Pydantic.internal import pydantic_internal_ldap_auth, pydantic_request_login_auth

# services
from core.services.serviceLogger import service_logger, service_logger_debug

class service_ldap:
    @staticmethod
    def init(pydantic_data: pydantic_request_login_auth, directory_source_pid: str) -> bool:
        """Authenticate user against LDAP directory."""
        # Retrieve LDAP connection details from the database
        ldap_connection_details = service_ldap.get_directory_connector(directory_source_pid)
        
        if not ldap_connection_details:
            reason = f"Directory connector not found or not enabled for PID: {directory_source_pid}"
            service_logger().critical(f"*** Unable to verify user | event=login | login_name={pydantic_data.login_name} | source_ip_address={pydantic_data.source_ip_address} | reason={reason}")
            return False

        if class_configuration().return_app_debug_mode():
            service_logger_debug().debug(ldap_connection_details)

        # Prepare LDAP server data
        ldap_server_data = {
            "base_distinguished_name": ldap_connection_details['base_distinguished_name'],
            "bind_username_fetched": f'{ldap_connection_details["netbios_hostname"]}\\{pydantic_data.login_name}',
            "bind_password": pydantic_data.password,
            "source_ip_address": pydantic_data.source_ip_address,
            "server_ip_or_name": ldap_connection_details['server_ip_or_name'],
            "replica_server_ip_or_name": ldap_connection_details['replica_server_ip_or_name'],
            "server_port": ldap_connection_details['server_port'],
            "connect_timeout": ldap_connection_details['connect_timeout'],
            "server_identity_check": ldap_connection_details['server_identity_check'],
            "certificate": ldap_connection_details['certificate']
        }

        directory_data = pydantic_internal_ldap_auth(**ldap_server_data)

        # Choose authentication method based on connection security
        if not ldap_connection_details['secure_connection']:
            return service_ldap.test_ldap_authentication(directory_data)
        else:
            return service_ldap.test_ldaps_authentication(directory_data)

    @staticmethod
    def get_directory_connector(directory_source_pid: str) -> dict:
        """Retrieve LDAP directory connector details from the database."""
        try:
            ldap_connector = dbprovider.query(ModelAdministrationUserManagementDirectoryConnector)\
                .filter(ModelAdministrationUserManagementDirectoryConnector.public_id == directory_source_pid)\
                    .first()

            if ldap_connector:
                return {
                    'base_distinguished_name': ldap_connector.base_distinguished_name,
                    'netbios_hostname': ldap_connector.netbios_hostname,
                    'server_ip_or_name': ldap_connector.server_ip_or_name,
                    'replica_server_ip_or_name': ldap_connector.replica_server_ip_or_name,
                    'server_port': ldap_connector.server_port,
                    'connect_timeout': ldap_connector.connect_timeout,
                    'server_identity_check': ldap_connector.server_identity_check,
                    'certificate': ldap_connector.certificate,
                    'secure_connection': ldap_connector.secure_connection
                }
            else:
                return None
        
        except Exception as e:
            service_logger().error(f"*** Exception while retrieving LDAP connector: {e}")
            raise HTTPException(status_code=500, detail="An error occurred while retrieving LDAP connector details") from e

    @staticmethod
    def test_ldap_authentication(directory_data: pydantic_internal_ldap_auth) -> bool:
        """Test LDAP authentication without SSL."""
        validation_status = False

        try:
            # Define servers and pool
            servers = [
                Server(host=directory_data.server_ip_or_name, port=directory_data.server_port, connect_timeout=directory_data.connect_timeout, use_ssl=False, get_info=NONE)
            ]
            if directory_data.replica_server_ip_or_name:
                servers.append(Server(host=directory_data.replica_server_ip_or_name, port=directory_data.server_port, connect_timeout=directory_data.connect_timeout, use_ssl=False, get_info=NONE))
                server_pool = ServerPool(servers=servers, pool_strategy=RANDOM, active=1, exhaust=20)
            else:
                server_pool = Server(host=directory_data.server_ip_or_name, port=directory_data.server_port, connect_timeout=directory_data.connect_timeout, use_ssl=False, get_info=NONE)

            # Connect to server
            connection = Connection(server_pool, user=directory_data.bind_username_fetched, password=directory_data.bind_password, authentication=NTLM, raise_exceptions=True, read_only=True)
            if connection.bind():
                service_logger().info(f"*** Successful authentication to directory connector | event=login | username={directory_data.bind_username_fetched} | source_ip_address={directory_data.source_ip_address} | reason=null")
                validation_status = True
            else:
                service_logger().warning(f"*** Cannot bind to directory connector | event=login | username={directory_data.bind_username_fetched} | source_ip_address={directory_data.source_ip_address} | reason={connection.last_error}")

        except LDAPSocketOpenError:
            service_logger().error(f"*** Cannot bind to directory connector | event=login | username={directory_data.bind_username_fetched} | source_ip_address={directory_data.source_ip_address} | reason='socket ssl wrapping error - 54'")
        except LDAPStartTLSError:
            service_logger().error(f"*** Cannot bind to directory connector | event=login | username={directory_data.bind_username_fetched} | source_ip_address={directory_data.source_ip_address} | reason='sslv3 handshake failure'")
        except LDAPInvalidCredentialsResult:
            service_logger().error(f"*** Cannot bind to directory connector | event=login | username={directory_data.bind_username_fetched} | source_ip_address={directory_data.source_ip_address} | reason='invalid Credentials - 49'")
        except Exception as error:
            service_logger().error(f"*** Cannot bind to directory connector | event=login | username={directory_data.bind_username_fetched} | source_ip_address={directory_data.source_ip_address} | reason='{error}'")
        finally:
            if 'connection' in locals():
                connection.unbind()
            return validation_status

    @staticmethod
    def test_ldaps_authentication(directory_data: pydantic_internal_ldap_auth) -> bool:
        """Test LDAPS authentication with SSL."""
        validation_status = False

        try:
            # Set up TLS configuration
            tls_configuration = Tls(
                validate=ssl.CERT_REQUIRED if directory_data.server_identity_check and directory_data.certificate else ssl.CERT_NONE,
                version=ssl.PROTOCOL_TLSv1_2,
                ca_certs_data=directory_data.certificate if directory_data.certificate else None,
            )

            # Define servers and pool
            servers = [
                Server(host=directory_data.server_ip_or_name, port=directory_data.server_port, connect_timeout=directory_data.connect_timeout, use_ssl=True, tls=tls_configuration, get_info=NONE)
            ]
            if directory_data.replica_server_ip_or_name:
                servers.append(Server(host=directory_data.replica_server_ip_or_name, port=directory_data.server_port, connect_timeout=directory_data.connect_timeout, use_ssl=True, tls=tls_configuration, get_info=NONE))
                server_pool = ServerPool(servers=servers, pool_strategy=RANDOM, active=1, exhaust=20)
            else:
                server_pool = Server(host=directory_data.server_ip_or_name, port=directory_data.server_port, connect_timeout=directory_data.connect_timeout, use_ssl=True, tls=tls_configuration, get_info=NONE)

            # Connect to server
            connection = Connection(server_pool, user=directory_data.bind_username_fetched, password=directory_data.bind_password, authentication=SIMPLE, raise_exceptions=True, read_only=True)
            connection.open()
            connection.start_tls()

            if connection.bind():
                service_logger().info(f"*** Successful authentication to directory connector via LDAPS | event=login | username={directory_data.bind_username_fetched} | source_ip_address={directory_data.source_ip_address} | reason=null")
                validation_status = True
            else:
                service_logger().warning(f"*** Cannot bind to directory connector via LDAPS | event=login | username={directory_data.bind_username_fetched} | source_ip_address={directory_data.source_ip_address} | reason='{connection.last_error}'")

        except LDAPSocketOpenError:
            service_logger().error(f"*** Cannot bind to directory connector via LDAPS | event=login | username={directory_data.bind_username_fetched} | source_ip_address={directory_data.source_ip_address} | reason='socket ssl wrapping error - 54'")
        except LDAPStartTLSError:
            service_logger().error(f"*** Cannot bind to directory connector via LDAPS | event=login | username={directory_data.bind_username_fetched} | source_ip_address={directory_data.source_ip_address} | reason='sslv3 handshake failure'")
        except LDAPInvalidCredentialsResult:
            service_logger().error(f"*** Cannot bind to directory connector via LDAPS | event=login | username={directory_data.bind_username_fetched} | source_ip_address={directory_data.source_ip_address} | reason='invalid Credentials - 49'")
        except Exception as error:
            service_logger().error(f"*** Cannot bind to directory connector via LDAPS | event=login | username={directory_data.bind_username_fetched} | source_ip_address={directory_data.source_ip_address} | reason='{error}'")
        finally:
            if 'connection' in locals():
                connection.unbind()
            return validation_status
