from django.shortcuts import render, redirect, HttpResponse
from .forms import RegistrationForm
from .models import Account
from django.contrib import messages, auth
from django.contrib.auth.decorators import login_required

#verification send email
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMessage

# Create your views here.

def register(request):
    if request.method =='POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            phone_number = form.cleaned_data['phone_number']
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            username = email.split("@")[0]+phone_number[:5]
            # we create a user using the the CREATE_USER method from MYACCOUNTMANAGER in the models.py
            user = Account.objects.create_user(first_name=first_name, 
                                               last_name=last_name, 
                                               email=email,
                                               username=username,
                                               password=password
                                               )
            user.phone_number = phone_number
            user.save()
            
            # USER ACCOUNT VERIFICATION / ACTIVATION
            current_site = get_current_site(request)
            mail_subject = 'Please activate your account'
            message = render_to_string('accounts/account_verification_email.html', {
                'user' : user,
                'domain' : current_site,
                'uid' : urlsafe_base64_encode(force_bytes(user.pk)),
                'token' : default_token_generator.make_token(user),
            })
            to_email = email
            send_email = EmailMessage(mail_subject, message, to=[to_email])
            send_email.send()
            
            
            # messages.success(request, 'Registration completed! Please check your Email to verify your account')
            return redirect('/accounts/login/?command=verification&email='+email)
    else:
        form = RegistrationForm()
    context = {
        'form' : form,
    }
    return render(request, 'accounts/register.html', context)


def activate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid)
    except(TypeError, ValueError, OverflowError, Account.DoesNotExist):
        user = None
        
    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, "Congratulations! Your account has been verified and it's activated \n Please login")
        return redirect('login_user')
    else:
        messages.error(request, 'Invalid activation link')
        return redirect('register')
    


def login_user(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']
        
        user = auth.authenticate(request, email=email, password=password)
        
        if user is not None:     
            auth.login(request, user)
            messages.success(request, 'You are  logged in')
            print(type(user))
            print(f'the user {user}')
            return redirect('dashboard')
        else:
            print(type(user))
            print(f'all  {user}')
            messages.error(request, 'Invalid login credentials')
            return redirect('login_user')
    else:
        return render(request, 'accounts/login.html')


@login_required(login_url='login_user')
def logout(request):
    auth.logout(request)
    messages.success(request, 'You are logged out!')
    return redirect('login_user')


@login_required(login_url='login_user')
def dashboard(request):
    return render(request, 'accounts/dashboard.html')


def forgotPassword(request):
    if request.method == 'POST':
        email = request.POST['email']
        if Account.objects.filter(email=email).exists():
            user = Account.objects.get(email__exact=email)
             # USER ACCOUNT VERIFICATION / ACTIVATION
            current_site = get_current_site(request)
            mail_subject = 'Please reset your password'
            message = render_to_string('accounts/reset_password_email.html', {
                'user' : user,
                'domain' : current_site,
                'uid' : urlsafe_base64_encode(force_bytes(user.pk)),
                'token' : default_token_generator.make_token(user),
            })
            to_email = email
            send_email = EmailMessage(mail_subject, message, to=[to_email])
            send_email.send()
            
            messages.success(request, 'Password reset link has been sent to you email address')
            return redirect('login_user')
        else:
            messages.error(request, 'Sorry! The account does not exist!!!')
            return redirect('forgotPassword')
    return render(request, 'accounts/forgotPassword.html')



def resetPassword_validate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid)
    except(TypeError, ValueError, OverflowError, Account.DoesNotExist):
        user = None
        
    if user is not None and default_token_generator.check_token(user, token):
        # save the session uid 
        uid = urlsafe_base64_decode(uidb64).decode()
        request.session['uid'] = uid
        messages.success(request, 'Please rest your password')
        return redirect('resetPassword')
    else:
        messages.error(request, 'This link is expired!!!')
        return redirect('login_user')
        
        
def resetPassword(request):
    if request.method == 'POST':
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']
        
        if password == confirm_password:
            uid = request.session.get('uid')
            user = Account.objects.get(pk=uid)
            user.set_password(password)
            user.save()
            messages.success(request, 'Password successfully reseted!!!')
            return redirect('login_user')
        else:
            messages.error(request, 'Password do not match')
            return redirect('forgotPassword')
    return render(request, 'accounts/resetPassword.html')