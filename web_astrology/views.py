from django.shortcuts import render, redirect
from django.contrib.auth import authenticate,login,logout
from accounts.models import User
from django.contrib import messages


# def HomePage(request):
#     return render(request, 'homepage.html')

def login_sys(request):
    if request.method == "POST":
        uname = request.POST['usernm']
        pwd = request.POST['password']
        
        user = authenticate(username=uname, password=pwd)
        # print(user.date_joined)

        if user:
            login(request, user)
            if user.is_active:
                if user.is_superuser:
                    return redirect('/admin-panel/index/')
                elif user.is_user:
                    return redirect('/')
            else:
                messages.warning(request, "Your are inactive user!")
                return redirect('/login/')
            
        else:
            messages.warning(request, "Invalid Userid and password")
            return redirect('/login/')
    
    return render(request, "login.html")
	

def logout_call(request):
	logout(request)
	return redirect('/')      #homepage