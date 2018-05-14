from datetime import datetime
from django.core.urlresolvers import reverse
from django.http import HttpResponse,HttpResponseRedirect
from django.shortcuts import render
from django import forms
from django.core.validators import RegexValidator

import ldap
import utils
import ConfigParser
import os
import logging
import urllib
import urlparse

# Set up configuration
from ss.exceptions import TokenException

project_path = os.path.realpath(os.path.dirname(__file__))
config_file = os.path.join(project_path, 'config.ini')

config_parser = ConfigParser.ConfigParser()
config_parser.read(config_file)

ldap_host = config_parser.get('default', 'ldap_host')
ldap_admin = config_parser.get('default', 'ldap_admin')
ldap_cred = config_parser.get('default', 'ldap_cred')
ldap_dn = config_parser.get('default', 'dn')
ldap_user_filter = config_parser.get('default', 'user_filter')

email_server = config_parser.get('default', 'email_server')
email_port = config_parser.get('default', 'email_port')
email_local_hostname = config_parser.get('default', 'email_local_hostname')
email_username = config_parser.get('default', 'email_username')
email_password = config_parser.get('default', 'email_password')
email_fromaddr = config_parser.get('default', 'email_fromaddr')

token_timeout_min = config_parser.getint('default', 'token_timeout_min')

# Set up logging
log = logging.getLogger(__name__)

def index(request):
    return render(request, 'ss/recover.html', {})


def send_recovery_email(request):
    """
    This function generates an email with a URL link that allows the user to perform a password recovery and reset.
    """
    class PasswordRecoveryForm(forms.Form):
        username = forms.CharField(label='Enter your username:', validators=[RegexValidator('^[a-zA-Z0-9]*$', message='Invalid username', code='invalid_username')])

    try:
        if request.method == 'GET':
            form = PasswordRecoveryForm()    
            return render(request, 'ss/recover.html', {'form': form})

        elif request.method == 'POST':
            form = PasswordRecoveryForm(request.POST)    

        if form.is_valid():
            username = form.cleaned_data.get('username')
            email, token = utils.set_token(ldap_host, ldap_admin, ldap_cred, ldap_dn, username, ldap_user_filter)
            subject = 'Password Recovery'
            full_path = request.get_full_path()
            parsed_url = urlparse.urlparse(full_path)

            pathparts = str.split(str(parsed_url.path),'/')
            baseurl = '/'.join(pathparts)

            token_timeout = token_timeout_min
            token_timeout_units = 'minutes'

            if (token_timeout_min > 60):
                token_timeout = token_timeout_min/60
                token_timeout_units = 'hours'

            message = '''
A request to recover your password has been received.
If you did not request this, please contact the administrators of the system.
If you did, you can complete the recovery process by clicking on the following link...
https://%s%s%s

This link will expire within %d %s.
            ''' % (request.get_host(), baseurl, token, token_timeout, token_timeout_units)
            log.error(message)

            #IF DEBUG, COMMENT OUT NEXT LINE
            #utils.send_email(email_server, email_port, email_local_hostname, email_username, email_password, email, email_fromaddr, subject, message)

            content = '''
Sent to email address associated with user, %s.

NOTE: The link in the email will expire in %d %s.
            ''' % (username, token_timeout, token_timeout_units)
            return render(request, 'ss/email_success.html', {'content': content})

    except Exception as e:
       log.exception(e)
       url = request.get_full_path()
       return render(request, 'ss/error.html', {'content': e, 'url': url})

    return render(request, 'ss/recover.html', {'form': form})
 
def reset_password(request, token):
    """
    Using the unique token supplied, this function allows the user to set his/her password without knowing their previous password.  Between the token and valid username, the user will be able to set his/her password.
    """
    class ResetPasswordForm(forms.Form):
        username = forms.CharField(label='Enter your username:', required=True, validators=[RegexValidator('^[a-zA-Z0-9]*$', message='Invalid username', code='invalid_username')],)
        passwd = forms.CharField(label='New Password:', required=True, widget=forms.PasswordInput)
        confirm = forms.CharField(label='Confirm Password:', required=True, widget=forms.PasswordInput)

        def clean(self):
            username = self.cleaned_data.get("username")
            passwd = self.cleaned_data.get("passwd")
            confirm = self.cleaned_data.get("confirm")

            log.debug('Reseting %s with %s, %s' % (username, passwd, confirm))

            if passwd != confirm:
                log.debug("Passwords do not match!")
                raise forms.ValidationError("Passwords do not match!")

            return self.cleaned_data

    if request.method == 'GET':
        form = ResetPasswordForm()

    elif request.method == 'POST':
        form = ResetPasswordForm(request.POST)

        if form.is_valid():
            token = urllib.unquote(token)
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('passwd') 
            confirm = form.cleaned_data.get('confirm')

            try:
                log.debug('Reseting %s with token %s' % (username, token))
                utils.reset_passwd_by_token(ldap_host, ldap_admin, ldap_cred, ldap_dn, username, ldap_user_filter, token, password, token_timeout_min)
                log.debug("Recovered success, for %s." % (username))
                utils.record_recovery_status(username, 'RESET')
                return render(request, 'ss/recovered_success.html')

            except Exception as e:
                err = 'Failed to reset password for %s.  The caught exception was %s' % (username, e.message)
                log.exception(err)
                info=''
                desc=''
                msg=''
                error_page='ss/error.html'

                if isinstance(e, ldap.CONSTRAINT_VIOLATION):
                    info = e.message['info']
                    desc = e.message['desc']
                    msg =  '''Unable to reset your password, %s (%s).''' % (info, desc)

                elif isinstance(e, ldap.UNWILLING_TO_PERFORM):
                    info = e.message['info']
                    desc = e.message['desc']
                    msg =  '''Unable to reset your password, %s (%s).  Please try again at a later time.''' % (info, desc)

                elif isinstance(e, TokenException):
                    error_page='ss/token_error.html'
                    msg = e.message

                else:
                    error_page='ss/token_error.html'
                    msg = e.message

                try:
                    utils.record_recovery_status(username, 'ERROR: ' + str(e.message))

                except Exception as e:
                    log.exception(e)

                return render(request, error_page, {'content': msg})

    return render(request, 'ss/recover.html', {'form': form})
        
def change_password(request):
    """
    This function changes the user's password using user inputs of username, current password, and new password with confirmation.
    """
    class ChangePasswordForm(forms.Form):
        username = forms.CharField(label='Enter your username:', validators=[RegexValidator('^[a-zA-Z0-9]*$', message='Invalid username', code='invalid_username')])
        old_passwd  = forms.CharField(label='Current Password:', widget=forms.PasswordInput)
        passwd  = forms.CharField(label='New Password:', widget=forms.PasswordInput)
        confirm = forms.CharField(label='Confirm Password:', widget=forms.PasswordInput)
 
        def clean(self):
            # cleaned_data = super(ChangePasswordForm, self).clean()
            username = self.cleaned_data.get("username")
            current_passwd = self.cleaned_data.get("old_passwd")
            passwd = self.cleaned_data.get("passwd")
            confirm = self.cleaned_data.get("confirm")

            if username:
                # Only do something if all fields are valid so far.
                if passwd != confirm:
                    raise forms.ValidationError("Passwords do not match!")

            return self.cleaned_data

    if request.method == 'GET':
        form = ChangePasswordForm()
    elif request.method == 'POST':
        form = ChangePasswordForm(request.POST)
        if form.is_valid():

            try:
                username = form.cleaned_data.get('username')
                old = form.cleaned_data.get('old_passwd')
                new = form.cleaned_data.get('passwd')
                utils.change_password(ldap_host, ldap_dn, ldap_admin, ldap_cred, username, ldap_user_filter, old, new)
                return render(request, 'ss/password_change_success.html')

            except Exception as e:
                log.error(e)
                err = 'Failed to reset password for %s.  The caught exception was %s' % (username, e.message)
                log.error(err)
                info=''
                desc=''
                msg='Unable to change your password.'

                if (isinstance(e, ldap.CONSTRAINT_VIOLATION)):
                    info = e.message['info']
                    desc = e.message['desc']
                    msg =  '''Unable to change your password, %s (%s).''' % (info, desc)

                if (isinstance(e, ldap.INVALID_CREDENTIALS)):
                    desc = e.message['desc']
                    msg =  '''Unable to change your password, %s.''' %  (desc)

                return render(request, 'ss/error.html', {'content': msg})

    return render(request, 'ss/change_password.html', {'form': form})

