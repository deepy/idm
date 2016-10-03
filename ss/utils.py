import ldap
import datetime
import logging
import base64
import smtplib
import email
import csv
import time
import os
import random, string

from ss.exceptions import TokenException

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

timeformat = '%Y%m%d%H%MZ'
tmp_password = ''.join(random.choice(string.ascii_uppercase) for _ in range(10))
token_attr = 'employeeNumber'
recovery_log = os.path.join(os.path.dirname(__file__),'password_recovery.log')

ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

# Error Strings
token_not_verified_error = 'The security token in the URL is invalid.  Please request a new, valid token from the password recovery link.'

def set_token(host, admin, cred, dn, user, user_group):
    """
    Using the connection parameters and username, this function sets a unique token for the LDAP user.  This token will be used, in part, to verify the user requested a password recovery.
    :param host: hostname of the LDAP directory service
    :param admin: username of the administrator that has permission to update a user record in the LDAP to set the token
    :param cred: password of the admin user
    :param dn: root search DN
    :param user: username (typically, uid)
    """

    try:
        ldap.set_option(ldap.OPT_DEBUG_LEVEL,255)
        url = 'ldaps://%s:636' % host
        l = ldap.initialize(url)
        log.debug("Connecting to %s as %s %s" % (url,admin,cred))
        l.simple_bind_s(admin, cred)
        log.debug("Bind successful")
        filter='(& (uid=%s) (memberOf=%s) )' % (user, user_group)
        attr=['uid', 'mail', token_attr]
        id = l.search(dn, ldap.SCOPE_SUBTREE, filter, attr)
        email = ''
        token = ''
        groups = []

        # The result set should only have a single, valid entry or none
        result_type, result_data = l.result(id,1)
        if (result_data == []):
            raise ldap.LDAPError('%s not a valid user' % user)

        else:
            log.debug(result_data)
            record=result_data[0][1]
            userdn = result_data[0][0]
            log.debug('Found dn, %s for user %s', userdn, user)
            logging.debug(record)
            email = record['mail'][0]
            log.debug(record['mail'][0])
            log.debug(record['uid'][0])

            # Create a temporary token using a time stamp and the username
            now = datetime.datetime.utcnow().strftime(timeformat)
            token = base64.urlsafe_b64encode(now)

        if token_attr in record:
            mod_attrs = [( ldap.MOD_REPLACE, token_attr, token)]
            l.modify_s(userdn, mod_attrs)
        else:
            mod_attrs = [( ldap.MOD_ADD, token_attr, token)]
            l.modify_s(userdn, mod_attrs)

            # RLJ look into compare() function for token
        # RLJ consider using the _ext_s for LDAPv3, synchronous

        l.unbind_s()

        # RLJ change the token for the email URL
        token = token.replace('=', '%3D')
        return (email, token)


    except KeyError as e:
        log.exception(e)
        raise Exception("Cannot change user's email at this time.")

    except ldap.LDAPError,e:
        log.exception(e)
        raise e

def reset_passwd_by_token(host, admin, cred, dn, user, user_group, token, passwd, token_timeout_min=60):
    """
    This function validates the token, sets the user's password temporarily, and binds as the user to perform a proper password change as the user
    :param host: hostname of the LDAP directory service
    :param admin: username of the administrator that has permission to update a user record in the LDAP to set the token
    :param cred: password of the admin user
    :param dn: root search DN
    :param user: username (typically, uid)
    :param token: token provided to the user (by email)
    :param passwd: new password supplied by user
    """

    try:
        log.debug('reset_passwd_by_token for user, %s' % user)

        url = 'ldaps://%s:636' % host
        l = ldap.initialize(url)
        l.simple_bind_s(admin, cred)
        #filter='uid=%s' % user
        filter='(& (uid=%s) (memberOf=%s) )' % (user, user_group)
        attr=['uid', 'mail', token_attr]
        id = l.search(dn, ldap.SCOPE_SUBTREE, filter, attr)

        # Get only one record from list, since there is only one user for a particular uid
        result_type, result_data = l.result(id,1)

        temp_password_set = False

        userdn=''

        if (result_data != []):
            record = result_data[0][1]
            userdn = result_data[0][0]
            valid_token = record[token_attr][0]

            log.debug(userdn)

            log.debug('Found user, %s' % userdn)
            log.debug('Security token, valid=%s and url-based=%s', valid_token, token)
            if (token == valid_token):
                log.debug('Verified token, valid=%s and url-based=%s', valid_token, token)

                # Test token for expiration
                token_time = datetime.datetime.strptime(base64.urlsafe_b64decode(valid_token), timeformat)
                expire_time = datetime.timedelta(minutes=token_timeout_min)
                now = datetime.datetime.utcnow()
                delta = now - token_time

                if expire_time > delta:
                    # Change the user's password
                    l.passwd_s(userdn, None, tmp_password)
                    temp_password_set = True
                    log.debug('Changed user password to temporary password')
                
                else:
                    # User did not respond to email soon enough
                    mod_attrs = [( ldap.MOD_DELETE, token_attr, None)]
                    l.modify_s(userdn, mod_attrs)
                    log.debug('User too slow in responding to email.')
                    raise TokenException('Token expired')
            
            else:
                log.debug("Token not valid")
                log.error(token_not_verified_error)
                raise TokenException(token_not_verified_error)

        else:
            l.unbind_s()
            raise Exception("User not found!")

        l.unbind_s()

        # Login as user with new, temporary password and set password
        if temp_password_set:
            try:
                log.debug("Changing password.")
                userconn = ldap.initialize(url)
                log.debug('Binding as user, %s' % userdn)
                userconn.simple_bind_s(userdn,tmp_password)
                userconn.passwd_s(userdn, tmp_password, passwd)
                userconn.unbind_s()
            except Exception as e:
                log.exception(e)
                raise e

    except KeyError as e:
        log.exception(e)
        raise Exception("Cannot change user's password at this time!")

    except Exception as e:
        log.exception(e)
        raise e


def change_password(host, dn, admin, cred, username, user_group, old, new):
    """
    This function changes a users password from old to new.
    :param host: hostname of the LDAP directory service
    :param dn: root search DN
    :param username: username (typically, uid)
    :param old: old password
    :param new: new password
    """

    ldap_url = 'ldaps://%s:636' % host
    try:
        userdn = get_userdn(host, dn, admin, cred, username, user_group)
        log.debug('userdn = %s' % userdn)
 
        log.debug('Connecting to %s.' % ldap_url)
        userconn = ldap.initialize(ldap_url)
        log.debug('Binding as user, %s' % userdn)
        userconn.simple_bind_s(userdn, old)
        userconn.passwd_s(userdn, old, new)
        userconn.unbind_s()

    except ldap.LDAPError as e:
        log.exception(e)
        raise e

def send_email(server, port, local_hostname, username, password, to_addr, from_addr, subject, message):
    """
    Utility function to send an email.
    """
    try:
        msg = email.MIMEMultipart.MIMEMultipart()
        msg['From'] = from_addr
        msg['To'] = to_addr
        msg['Subject'] = subject
        msg.attach(email.MIMEText.MIMEText(message,'plain'))
        server = smtplib.SMTP_SSL(server, port, local_hostname)
        server.set_debuglevel(1)
        server.login(username,password)
        error = server.sendmail(from_addr, to_addr, msg.as_string())
        server.quit()
    except Exception as e:
        log.exception(e)
        raise Exception("An error occured while attempting to send email.  Please notify the system administrators of this issue.")

def record_recovery_status(user, status):
    """
    This function records the status of a user's password recovery.
    :param user: user that requested recovery
    :param status: status of the recovery request
    """
    with open(recovery_log, 'ab') as recovery_log_file:
       wr = csv.writer(recovery_log_file, quoting=csv.QUOTE_MINIMAL) 
       tformat = '%Y-%m-%d %H:%M:%SZ'
       now = datetime.datetime.utcnow().strftime(tformat)
       wr.writerow([now, user, status])

def get_userdn(host, dn, admin, cred, userid, user_group):
    """
    Get the user's dn.
    param host: LDAP host
    param dn: search DN
    param userid: userid
    return: if found, the user's DN
    """
    ldap_url = 'ldaps://%s:636' % host
    log.debug('*** %s', user_group)
    try:
        log.debug('Connecting to %s' % ldap_url)
        l = ldap.initialize(ldap_url)
        #filter='uid=%s' % userid
        l.simple_bind_s(admin, cred)
        filter='(& (uid=%s) (memberOf=%s) )' % (userid, user_group)
        id = l.search(dn, ldap.SCOPE_SUBTREE, filter, None)
        result_type, result_data = l.result(id,1)
    
        if (result_data == []):
            raise ldap.LDAPError('%s is not a valid user' % userid)
        else:
            userdn = result_data[0][0]
            log.debug('Found dn, %s for user %s', userdn, userid)
            return userdn

    except ldap.LDAPError as e:
        log.exception(e)
        raise e

    finally:
        log.debug('********************* unbinding')
        l.unbind_s()
   
