from django.shortcuts import render,redirect,HttpResponse
from django.urls import reverse

from web_astrology import settings
from .models import *
from accounts.models import *
from userapp.models import *
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from datetime import datetime
# Create your views here.
from django.db.models import Q
import os
from django.contrib.auth.hashers import make_password
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from phonepe.sdk.pg.payments.v1.payment_client import PhonePePaymentClient
import uuid
from phonepe.sdk.pg.payments.v1.models.request.pg_pay_request import PgPayRequest


@login_required(login_url='/login/')
def Homepage(request):
    no_of_user = User.objects.all().count()
    pandit = CreatePandit.objects.all().count()
    cateofprod = CategoryOfProduct.objects.all().count()
    prod = Products.objects.all().count()
    cateofpuja = CategoryOfPooja.objects.all().count()
    pujaslot = PoojaSlot.objects.all().count()
    pujaobj = Pooja.objects.all().count()
    prodorder = Order.objects.all().count()
    pujaordrt = PoojaOrder.objects.all().count()
    catefaq = CategoryOfFAQ.objects.all().count()
    qus = QusAndAnswer.objects.all().count()
    
    pedingpuj = PoojaOrder.objects.filter(order_status=False).count()
    pedingord = Order.objects.filter(order_status=False).count()
    pedingans = QusAndAnswer.objects.filter(is_answered=False).count()
    outofstock = Products.objects.filter(quantity=0).count()
    todayorder = Order.objects.filter(orderdate=datetime.today()).count()
    logedin =User.objects.get(id=request.user.id)
    
    print(logedin)
    return render(request, "admintemp/index.html", {'user':no_of_user,
                                                    'pandit':pandit,
                                                    'cateofprod':cateofprod,
                                                    'prod':prod,
                                                    'cateofpuja':cateofpuja,
                                                    'pujaslot':pujaslot,
                                                    'pujaobj':pujaobj,
                                                    'prodorder':prodorder,
                                                    'pujaordrt':pujaordrt,
                                                    'catefaq':catefaq,
                                                    'qus':qus,
                                                    'pedingpuj':pedingpuj,
                                                    'pedingord':pedingord,
                                                    'pedingans':pedingans,
                                                    'outofstock':outofstock,
                                                    'todayorder':todayorder,
                                                     })   #, 'ass':patientass


def GetPendingOrder(request):
    pedingord = Order.objects.filter(order_status=False)
    return render(request, "admintemp/pendingorder.html", {'pedingord':pedingord})
    
    
def GetPendingPujaBook(request):
    pedingpuja = PoojaOrder.objects.filter(order_status=False)
    return render(request, "admintemp/pendingpuja.html", {'pedingpuja':pedingpuja})
    

# def Login(request):
#     if request.method == "POST":
#         uname = request.POST['username']
#         pwd = request.POST['password']
#         print(uname)
#         user = authenticate(username=uname, password=pwd)
#         # print(user.date_joined)

#         if user:
#             login(request, user)
#             if user.is_superuser:
#                 return redirect('/admin-panel/index/')
#             # elif user.is_staff:                                 # Admin
#             #     return redirect('/admins/')
#             # elif user.is_manager:
#             #     return redirect('/leadadmin/')
            
#         else:
#             return redirect('/')
    
#     return render(request, "login.html")

def ForgotPassword(request,id):
    print('id',id)
    oldpwd=User.objects.get(id=id)
    print('id',oldpwd.id)
    print('kdfjv',oldpwd.password)
    if request.method == "POST":
        newpwd = request.POST['newpassword']
        print(newpwd)
        uplead = User.objects.filter(id=id)
        print("working...............")
        uplead.update(password=make_password(newpwd))
        messages.success(request,"Password changed")
        logout(request)
        return redirect('/admin-panel/')
    else:
        edtad=User.objects.get(id=id)
        print(edtad)
        return render(request,'admintemp/changepassword.html',{'edtad':edtad, 'oldpwd':oldpwd})

    

        

def logout_call(request):
    logout(request)
    return redirect('/admin-panel/')

def GetAllUsers(request):
    if 'q' in request.GET:
        q = request.GET['q']
        # data = Data.objects.filter(last_name__icontains=q)
        multiple_q = Q(Q(first_name__contains=q) | Q(last_name__contains=q) | Q(username__contains=q) | Q(contactno__contains=q))
        data = User.objects.filter(multiple_q)
        
        # print("ewfweewdfewew  :fwfw", data[0].email)
        context = {
            'data': data,
        }
        return render(request, "admintemp/searchuser-table.html",context)
    else:
        users = User.objects.filter(is_user=True, is_superuser=False).order_by('-id')
        
        paginator = Paginator(users, 6)
        page_number = request.GET.get('page')
        all_lead = paginator.get_page(page_number)
        totalpage = all_lead.paginator.num_pages
        
        context = {
            'all_lead':all_lead,
            'lastpage':totalpage,
            'totalPagelist':[n+1 for n in range(totalpage)],
            'users':users
        }
        return render(request, "admintemp/user-table.html", context)
    
def UpdateUser(request, id):
    # my_users = User.objects.all()
    # print(my_users)
    if request.method == 'POST':
        name = request.POST['fname']
        lname = request.POST['lname']
        email = request.POST['email']
        # username = request.POST['usernm']
        mobno = request.POST['phone_no']
        status = request.POST['is_active']
        gender = request.POST['gender']
        # profilimg = request.FILES['profile']
        
        
        
        uplead = User.objects.filter(id=id)
        
        uplead.update(first_name=name, last_name=lname, email=email, contactno=mobno,is_active=status,gender=gender)
        # messages.success(request, f"{name}, profile updated successfully")
        return redirect('/admin-panel/getusers/')
        # return redirect(request.META.get('HTTP_REFERER', 'redirect_if_referer_not_found'))  
    else:
        getUser = User.objects.get(id=id)    
        return render(request, "admintemp/edituser.html", {'user':getUser})
        
def ViewProfiled(request, id):
    profile = User.objects.get(id=id)
    print(profile)
    return render(request, "admintemp/profileget.html", {'user':profile})
    
def DeleteUser(request, id):
    data = User.objects.get(id=id)
    data.delete()
    # messages.success(request, f"{data.fullname}, has been deleted succsessfull")
    return redirect('/admin-panel/getusers/')



def CreatePanditJi(request):
    if request.method == 'POST':
        nm = request.POST['name']
        exp = request.POST['experience']
        lang = request.POST['languages']
        exper = request.POST['expertise_in']
        abt = request.POST['about']
        mob = request.POST['contact']
        pic = request.FILES['panditpicture']
        
        if CreatePandit.objects.filter(contact=mob).exists():
                messages.info(request, 'Mobbile number is already taken')
                return redirect('/admin-panel/addpandit/')
        else:
            newclub = CreatePandit(name=nm ,experience=exp ,languages=lang ,expertise_in=exper , about=abt , contact=mob , panditpicture=pic)
            newclub.save()
            # messages.info(request, 'Pandit Added Successfull')
        return redirect('/admin-panel/addpandit/')
    
    else:
        return render(request, "admintemp/createpandit.html")
    
    
def GetAllPandit(request):
    users = CreatePandit.objects.all().order_by('-id')
    return render(request, "admintemp/panditlist.html", {'users':users})

def UpdatePandit(request, id):
    if request.method == 'POST':
        nm = request.POST['name']
        exp = request.POST['experience']
        lang = request.POST['languages']
        exper = request.POST['expertise_in']
        abt = request.POST['about']
        mob = request.POST['contact']
        
        uplead = CreatePandit.objects.filter(id=id)
        
        uplead.update(name=nm ,experience=exp ,languages=lang ,expertise_in=exper , about=abt , contact=mob)
        # messages.success(request, f"Updated Successfully")
        return redirect('/admin-panel/getpandit/')
        # return redirect(request.META.get('HTTP_REFERER', 'redirect_if_referer_not_found'))  
    else:
        getUser = CreatePandit.objects.get(id=id)    
        return render(request, "admintemp/editpandit.html", {'user':getUser})
    
    
def DeletePandit(request, id):
    data = CreatePandit.objects.get(id=id)
    data.delete()
    # messages.success(request, "Deleted succsessfull")
    return redirect('/admin-panel/getpandit/')




def CategoryOfProductView(request):
    if request.method == 'POST':
        prodcat = request.POST['catname']
        # status = request.POST['active_status']
        
        if CategoryOfProduct.objects.filter(catprod=prodcat).exists():
                # messages.info(request, 'Category is already taken')
                return redirect('/admin-panel/addcategory/')
        else:
            newclub = CategoryOfProduct(catprod=prodcat,active_status=True)
            newclub.save()
            # messages.info(request, 'Category Added Successfull')
        return redirect('/admin-panel/getcategory/')
    
    else:
        return render(request, "admintemp/createproductcate.html")
    
    
def GetAllCategoryOfProduct(request):
    users = CategoryOfProduct.objects.all().order_by('-id')
    
    paginator = Paginator(users, 6)
    page_number = request.GET.get('page')
    all_lead = paginator.get_page(page_number)
    totalpage = all_lead.paginator.num_pages
    
    context = {
        'all_lead':all_lead,
        'lastpage':totalpage,
        'totalPagelist':[n+1 for n in range(totalpage)],
        'users':users
    }
    return render(request, "admintemp/productcategory.html", context)

def UpdateCategoryOfProduct(request, id):
    # my_users = User.objects.all()
    # print(my_users)
    if request.method == 'POST':
        prodcat = request.POST['catname']
        status = request.POST['active_status']
        
        uplead = CategoryOfProduct.objects.filter(id=id)
        
        uplead.update(catprod=prodcat,active_status=status)
        # messages.success(request, f"Updated Successfully")
        # return redirect('/superadmin/edit_leadinfo//')
        return redirect('/admin-panel/getcategory/')  
    else:
        getUser = CategoryOfProduct.objects.get(id=id)    
        return render(request, "admintemp/editcategory.html", {'user':getUser})
    
    
def DeleteCategoryOfProduct(request, id):
    data = CategoryOfProduct.objects.get(id=id)
    data.delete()
    # messages.success(request, "Deleted succsessfull")
    return redirect('/admin-panel/getcategory/')



def CreateCategoryOfPooja(request):
    if request.method == 'POST':
        cat = request.POST['catname']
        catimg = request.FILES['catpic']
        # status = request.POST['active_status']
        
        
        
        if CategoryOfPooja.objects.filter(catname=cat).exists():
                # messages.info(request, 'Current role is already taken')
                return redirect('/admin-panel/addpujacategory/')
        else:
            newclub = CategoryOfPooja(catname=cat, prodpicture=catimg,active_status=True)
            newclub.save()
            # messages.info(request, 'Current role Added Successfull')
        return redirect('/admin-panel/getpujacategory/')
    
    else:
        return render(request, "admintemp/addpujacategory.html")
    
    
def GetAllCategoryOfPooja(request):
    users = CategoryOfPooja.objects.all().order_by('-id')
    
    paginator = Paginator(users, 6)
    page_number = request.GET.get('page')
    all_lead = paginator.get_page(page_number)
    totalpage = all_lead.paginator.num_pages
    
    context = {
        'all_lead':all_lead,
        'lastpage':totalpage,
        'totalPagelist':[n+1 for n in range(totalpage)],
        'users':users
    }
    return render(request, "admintemp/pujacategorylist.html", context)

def UpdateCategoryOfPooja(request, id):
    
    uplead = CategoryOfPooja.objects.filter(id=id)
    uplead1 = CategoryOfPooja.objects.get(id=id)
    
    if request.method == 'POST':
        cat = request.POST['catname']
        # catimg = request.FILES['catpic']
        status = request.POST['active_status']
        
        if len(request.FILES) !=0:
            if len(uplead1.prodpicture) > 0:
                print('yessssssssssssssss1')
                os.remove(uplead1.prodpicture.path)
                # print(uplead1.profilepicture.path)
            uplead1.prodpicture = request.FILES['catpic']
            uplead1.save()
        
        uplead = CategoryOfPooja.objects.filter(id=id)
        
        uplead.update(catname=cat,active_status=status)
        # messages.success(request, "Updated Successfully")
        # return redirect('/superadmin/edit_leadinfo//')
        return redirect('/admin-panel/getpujacategory/')  
    else:
        getUser = CategoryOfPooja.objects.get(id=id)    
        return render(request, "admintemp/editpujacategory.html", {'user':getUser})
    
    
def DeleteCategoryOfPooja(request, id):
    data = CategoryOfPooja.objects.get(id=id)
    data.delete()
    # messages.success(request, "Deleted succsessfull")
    return redirect('/admin-panel/getpujacategory/')





def CreateHoroscopeCategory(request):
    # print(my_users)
    if request.method == 'POST':
        cat = request.POST['name']
        catimg = request.FILES['catpic']
        ulead = HoroscopeCategory(catname=cat,horoscopeimg=catimg)
        ulead.save()
        # messages.success(request, "Horoscop category has been created successfully")
        return redirect('/admin-panel/gethoroscopcate/')
    else:
        return render(request, "admintemp/addhoroscopecategory.html")

def GetAllHoroscopeCategory(request):    
    horo = HoroscopeCategory.objects.all().order_by('-id')
    return render(request, "admintemp/horoscopcatelist.html", {'cate':horo})


def UpdateHoroscopeCategory(request, id):
    
    uplead = HoroscopeCategory.objects.filter(id=id)
    uplead1 = HoroscopeCategory.objects.get(id=id)
    
    if request.method == 'POST':
        cat = request.POST['catname']
        
        if len(request.FILES) !=0:
            if len(uplead1.horoscopeimg) > 0:
                print('yessssssssssssssss1')
                os.remove(uplead1.horoscopeimg.path)
                # print(uplead1.profilepicture.path)
            uplead1.horoscopeimg = request.FILES['catpic']
            uplead1.save()
        
        uplead = HoroscopeCategory.objects.filter(id=id)
        
        uplead.update(catname=cat)
        # messages.success(request, f"Updated Successfully")
        return redirect('/admin-panel/gethoroscopcate/')
        # return redirect(request.META.get('HTTP_REFERER', 'redirect_if_referer_not_found'))  
    else:
        getUser = HoroscopeCategory.objects.get(id=id)    
        return render(request, "admintemp/edithoroscopcategory.html", {'user':getUser})
    
    
def DeleteHoroscopeCategory(request, id):
    data = HoroscopeCategory.objects.get(id=id)
    data.delete()
    # messages.success(request, "Deleted succsessfull")
    return redirect('/admin-panel/gethoroscopcate/')



def CreateProducts(request):   
    
    catid = CategoryOfProduct.objects.all()
    if request.method == 'POST':
        fnm = request.POST['prodname']
        loc = request.POST['discription']
        gen = request.POST['price']
        dig1 = request.POST['quantity']
        dig2 = request.POST['category']
        dis = request.POST['offers']        
        uplod = request.FILES['prodpicture']
        # status = request.POST['active_status'] 
        
        cal = float(gen)-((float(gen)*float(dis))/100)
        
        ulead = Products(prodname=fnm,
                            prodpicture=uplod,
                            discription=loc,
                            price=gen,
                            quantity=dig1,
                            category_id=dig2,
                            offers=dis,
                            active_status=True,
                            offerprice=cal
                            )
        ulead.save()
        # messages.success(request, "Product has been created successfully")
        return redirect('/admin-panel/getproducts/')
    else:
        return render(request, "admintemp/addproductlist.html",{'category':catid})
    


def GetAllProducts(request):
    if 'q' in request.GET:
        q = request.GET['q']
        # data = Data.objects.filter(last_name__icontains=q)
        multiple_q = Q(Q(prodname__contains=q) | Q(prodpicture__contains=q) | Q(price__contains=q) | Q(offers__contains=q))
        data = Products.objects.filter(multiple_q)
        
        # print("ewfweewdfewew  :fwfw", data[0].email)
        context2 = {
            'data': data,
        }
        return render(request, "admintemp/searchproductlist.html",context2)
    prod = Products.objects.all().order_by('-id')
    
    paginator = Paginator(prod, 6)
    page_number = request.GET.get('page')
    all_lead = paginator.get_page(page_number)
    totalpage = all_lead.paginator.num_pages
    
    context = {
        'all_lead':all_lead,
        'lastpage':totalpage,
        'totalPagelist':[n+1 for n in range(totalpage)],
        'product':prod
    }
    
    
    
    
    return render(request, "admintemp/getproductlist.html", context)

def UpdateProducts(request, id):
    catid = CategoryOfProduct.objects.all()
    uplead = Products.objects.filter(id=id)
    uplead1 = Products.objects.get(id=id)
    
    
    my_users = User.objects.all()
    # upleid = Products.objects.get(id=id)
    if request.method == 'POST':
        fnm = request.POST['prodname']
        loc = request.POST['discription']
        gen = request.POST['price']
        dig1 = request.POST['quantity']
        dig2 = request.POST['category']
        dis = request.POST['offers']    
        status = request.POST['active_status'] 
        
        cal = float(gen)-((float(gen)*float(dis))/100)
        
        if len(request.FILES) !=0:
            if len(uplead1.prodpicture) > 0:
                print('yessssssssssssssss1')
                os.remove(uplead1.prodpicture.path)
                # print(uplead1.prodpicture.path)
            uplead1.prodpicture = request.FILES['prodpicture']
            uplead1.save()
        
        uplead = Products.objects.filter(id=id)
        
        uplead.update(prodname=fnm,
                            discription=loc,
                            price=gen,
                            quantity=dig1,
                            category=dig2,
                            offers=dis,
                            active_status=status,
                            offerprice=cal
                            )
        # messages.success(request, f"Updated Successfully")
        # return redirect('/superadmin/edit_leadinfo//')
        return redirect('/admin-panel/getproducts/')  
    else:
        getUser = Products.objects.get(id=id)    
        return render(request, "admintemp/editproductlist.html", {'user':getUser,'my_us':my_users, 'category':catid})



   
   
    
def DeleteProducts(request, id):
    data = Products.objects.get(id=id)
    data.delete()
    # messages.success(request, "Deleted succsessfull")
    return redirect('/admin-panel/getproducts/')


def CreatePooja(request):
    my_users = User.objects.all()
    pujacat = CategoryOfPooja.objects.all()
    if request.method == 'POST':
        fnm = request.POST['name']
        loc = request.FILES['pojaimage']
        gen = request.POST['discription']
        ass = request.POST['needofpuja']
        dig1 = request.POST['advantages']
        dig2 = request.POST['pujasamagri']
        dis = request.POST['category']
        inv = request.POST['price']
        treat = request.POST['offers']
        # status = request.POST['active_status']
        
        cal = float(inv)-((float(inv)*float(treat))/100)
        
        
        ulead = Pooja(name=fnm,
                            pojapicture=loc,
                            discription=gen,
                            needofpuja=ass,
                            advantages=dig1,
                            pujasamagri=dig2,
                            category_id=dis,
                            price=inv,
                            offers=treat,
                            active_status=True,
                            offerprice=cal
                            )
        ulead.save()
        # messages.success(request, "Pooja has been created successfully")
        return redirect('/admin-panel/getpuja/')
    else:
        return render(request, "admintemp/addPooja.html", {'users':my_users, 'poojacat':pujacat})






def GetAllPuja(request):
    pooja = Pooja.objects.all().order_by('-id')
    
    paginator = Paginator(pooja, 6)
    page_number = request.GET.get('page')
    all_lead = paginator.get_page(page_number)
    totalpage = all_lead.paginator.num_pages
    
    context = {
        'all_lead':all_lead,
        'lastpage':totalpage,
        'totalPagelist':[n+1 for n in range(totalpage)],
        'pujalst':pooja
    }
    
    return render(request, "admintemp/pujalist.html", context)

def UpdatePujaDetail(request, id):
    pujacat = CategoryOfPooja.objects.all()
    
    uplead = Pooja.objects.filter(id=id)
    uplead1 = Pooja.objects.get(id=id)
    if request.method == 'POST':
        fnm = request.POST['name']
        # loc = request.POST['pojapicture']
        gen = request.POST['discription']
        ass = request.POST['needofpuja']
        dig1 = request.POST['advantages']
        dig2 = request.POST['pujasamagri']
        dis = request.POST['category']
        inv = request.POST['price']
        treat = request.POST['offers']
        status = request.POST['active_status']
        cal = float(inv)-((float(inv)*float(treat))/100)
        
        if len(request.FILES) !=0:
            if len(uplead1.pojapicture) > 0:
                print('yessssssssssssssss1')
                os.remove(uplead1.pojapicture.path)
                # print(uplead1.pojapicture.path)
            uplead1.pojapicture = request.FILES['pojapicture']
            uplead1.save()
        
        uplead = Pooja.objects.filter(id=id)
        
        uplead.update(name=fnm,
                            # pojapicture=loc,
                            discription=gen,
                            needofpuja=ass,
                            advantages=dig1,
                            pujasamagri=dig2,
                            category_id=dis,
                            price=inv,
                            offers=treat,
                            active_status=status,
                            offerprice=cal
                            )
        # messages.success(request, f"Updated Successfully")
        # return redirect('/superadmin/edit_leadinfo//')
        return redirect('/admin-panel/getpuja/')  
    else:
        getPuja = Pooja.objects.get(id=id)    
        return render(request, "admintemp/editpujalist.html", {'pujaobj':getPuja, 'poojacat':pujacat})
    


# def PatientassDetail(request, id):
#        mykyc = Pooja.objects.get(id=id)
#        return render(request, "viewdetailassigned.html", {'mykyc':mykyc})
   
   
def DeletePujaDetail(request, id):
    data = Pooja.objects.get(id=id)
    data.delete()
    # messages.success(request, "Deleted succsessfull")
    return redirect('/admin-panel/getpuja/')





def GetAllProductOrder(request):    
    prodorder = Order.objects.all().order_by('id').reverse()
    return render(request, "admintemp/getorderslis.html", {'prodorder':prodorder})

def UpdateOrderDetail(request, id):
    
    if request.method == 'POST':
        fnm = request.POST['status']
        # loc = request.POST['pojapicture']
        # gen = request.POST['discription']
        # ass = request.POST['needofpuja']
        # dig1 = request.POST['advantages']
        # dig2 = request.POST['pujasamagri']
        # dis = request.POST['category']
        # inv = request.POST['price']
        # treat = request.POST['offers']
        
        uplead = Order.objects.filter(id=id)
        
        uplead.update(order_status=fnm,
                            # # pojapicture=loc,
                            # discription=gen,
                            # needofpuja=ass,
                            # advantages=dig1,
                            # pujasamagri=dig2,
                            # category_id=dis,
                            # price=inv,
                            # offers=treat
                            )
        # messages.success(request, f"Updated Successfully")
        return redirect('/admin-panel/getproductorder/')
        # return redirect(request.META.get('HTTP_REFERER', 'redirect_if_referer_not_found'))  
    else:
        getorder = Order.objects.get(id=id)    
        return render(request, "admintemp/editorderlist.html", {'order':getorder})

def GetViewprofile(request, id):
    user = Order.objects.get(id=id)
    print(user)
    return render(request, "admintemp/userprofile.html",{'getuser':user})

def GetAllPujaSlot(request):    
    pujabook = PoojaOrder.objects.all().order_by('id').reverse()
    print(pujabook)
    
    paginator = Paginator(pujabook, 6)
    page_number = request.GET.get('page')
    all_lead = paginator.get_page(page_number)
    totalpage = all_lead.paginator.num_pages
    
    context = {
        'all_lead':all_lead,
        'lastpage':totalpage,
        'totalPagelist':[n+1 for n in range(totalpage)],
        'pojaslot':pujabook
    }
    return render(request, "admintemp/getpoojaslotbook.html", context)

def UpdatPujabookDetail(request, id):
    
    if request.method == 'POST':
        fnm = request.POST['status']
        # loc = request.POST['pojapicture']
        # gen = request.POST['discription']
        # ass = request.POST['needofpuja']
        # dig1 = request.POST['advantages']
        # dig2 = request.POST['pujasamagri']
        # dis = request.POST['category']
        # inv = request.POST['price']
        # treat = request.POST['offers']
        
        uplead = PoojaOrder.objects.filter(id=id)
        
        uplead.update(order_status=fnm,
                            # # pojapicture=loc,
                            # discription=gen,
                            # needofpuja=ass,
                            # advantages=dig1,
                            # pujasamagri=dig2,
                            # category_id=dis,
                            # price=inv,
                            # offers=treat
                            )
        # messages.success(request, f"Updated Successfully")
        # return redirect('/superadmin/edit_leadinfo//')
        return redirect('/admin-panel/getpoojaslot/')  
    else:
        getpujabok = PoojaOrder.objects.get(id=id)    
        return render(request, "admintemp/editbookinglist.html", {'pujabok':getpujabok})
    
    
def GetViewPujaSlotprofile(request, id):
    user = PoojaOrder.objects.get(id=id)
    print(user)
    return render(request, "admintemp/userprofile.html",{'getuser':user})


def CategoryOfFAQView(request):
    if request.method == 'POST':
        faqcat = request.POST['catname']
        
        if CategoryOfFAQ.objects.filter(catname=faqcat).exists():
                # messages.info(request, 'FAQ Category is already taken')
                return redirect('/admin-panel/addfaqcategory/')
        else:
            newclub = CategoryOfFAQ(catname=faqcat)
            newclub.save()
            # messages.info(request, 'FAQ Category Added Successfull')
        return redirect('/admin-panel/getfaqcategory/')
    
    else:
        return render(request, "admintemp/createfaqcate.html")
    
    
def GetAllCategoryOfFAQ(request):
    faqcate = CategoryOfFAQ.objects.all().order_by('-id')
    return render(request, "admintemp/faqcategory.html", {'faq':faqcate})


def UpdateCategoryOfFAQ(request, id):
    # my_users = User.objects.all()
    # print(my_users)
    if request.method == 'POST':
        faqcate = request.POST['catname']
        
        uplead = CategoryOfFAQ.objects.filter(id=id)
        
        uplead.update(catname=faqcate)
        # messages.success(request, f"Updated Successfully")
        # return redirect('/superadmin/edit_leadinfo//')
        return redirect('/admin-panel/getfaqcategory/')  
    else:
        getUser = CategoryOfFAQ.objects.get(id=id)    
        return render(request, "admintemp/editfaqcategory.html", {'user':getUser})
    
def DeleteFAQDetail(request, id):
    data = CategoryOfFAQ.objects.get(id=id)
    data.delete()
    # messages.success(request, "Deleted succsessfull")
    return redirect('/admin-panel/getfaqcategory/')
    
    
    

def AskTimeOfFAQView(request):
    if request.method == 'POST':
        faqtime = request.POST['time']
        price = request.POST['price']
        faqexp = request.POST['exp']
        package = request.POST['package']
        icon = request.POST['icon']
        
        # if AnswerFAQTime.objects.filter(catname=fatime).exists():
        #         messages.info(request, 'FAQ Category is already taken')
        #         return redirect('/admin-panel/addfaqcategory/')
        # else:
        newclub = AnswerFAQTime(time=faqtime, price=price,exp=faqexp,package=package,icon=icon)
        newclub.save()
        # messages.info(request, 'FAQ time Added Successfull')
        return redirect('/admin-panel/getfaqasktime/')
    
    else:
        return render(request, "admintemp/createfaqprice.html")
    
    
def GetAllAskTimeOfFAQ(request):
    faqcate = AnswerFAQTime.objects.all().order_by('-id')
    return render(request, "admintemp/faqasktimeprice.html", {'faq':faqcate})


def UpdateAskTimeOfFAQ(request, id):
    # my_users = User.objects.all()
    # print(my_users)
    if request.method == 'POST':
        faqtime = request.POST['time']
        price = request.POST['price']
        faqexp = request.POST['exp']
        package = request.POST['package']
        icon = request.POST['icon']
        
        uplead = AnswerFAQTime.objects.filter(id=id)
        
        uplead.update(time=faqtime, price=price,exp=faqexp,package=package,icon=icon)
        # messages.success(request, f"Updated Successfully")
        return redirect('/admin-panel/getfaqasktime/')
        # return redirect(request.META.get('HTTP_REFERER', 'redirect_if_referer_not_found'))  
    else:
        getUser = AnswerFAQTime.objects.get(id=id)    
        return render(request, "admintemp/editfaqtimeprice.html", {'user':getUser})
    
def DeleteAskTimeFAQDetail(request, id):
    data = AnswerFAQTime.objects.get(id=id)
    data.delete()
    # messages.success(request, "Deleted succsessfull")
    return redirect('/admin-panel/getfaqasktime/')
    
    



# def CreateQusAndAnswer(request):
#     # my_cour = CategoryOfFAQ.objects.all()
#     # my_spe = AnswerFAQTime.objects.all()
#     # print(my_users)
#     if request.method == 'POST':
#         email = request.POST['category']
#         course = request.POST['qus']
#         specialist = request.user.id
#         college = request.POST['ans']
#         role = request.POST['role']
#         registration = request.POST['registration']
#         usr = request.POST['user']
        
#         ulead = FewMoreDetail(email=email,course_id=course,specialist_id=specialist,college=college,role=role,registration=registration,user_id=usr)
#         ulead.save()
#         messages.success(request, "Detail has been created successfully")
#         return redirect('/admin-panel/addmoredetails/')
#     else:
#         return render(request, "addfewmoredetail.html", {'users':my_user, 'spec':my_spe, 'cour':my_cour, 'rol':my_role})


def GetAllQusAndAnswerOfFAQ(request):
    faqask = QusAndAnswer.objects.all().order_by('-id')
    
    paginator = Paginator(faqask, 6)
    page_number = request.GET.get('page')
    all_lead = paginator.get_page(page_number)
    totalpage = all_lead.paginator.num_pages
    
    context = {
        'all_lead':all_lead,
        'lastpage':totalpage,
        'totalPagelist':[n+1 for n in range(totalpage)],
        'faq':faqask
    }
    return render(request, "admintemp/questionanslist.html", context)


def GetViewQusAndAnswerprofile(request, id):
    user = QusAndAnswer.objects.get(id=id)
    print(user)
    return render(request, "admintemp/userprofile.html",{'getuser':user})
    

def GetViewQusAndAnswerAskQus(request, id):
    user = QusAndAnswer.objects.get(id=id)
    print(user)
    return render(request, "admintemp/detailqushistory.html",{'getuser':user})



def UpdateQusAndAnswerDetail(request, id):
    # my_cour = Course.objects.all()
    # my_spe = Speciality.objects.all()
    # my_user = User.objects.all()
    # my_role = CurrentRole.objects.all()
    # print(my_role)
    # print(my_users)
    if request.method == 'POST':
        category = request.POST['category']
        answertime = request.POST['answertime']
        qus = request.POST['qus']
        is_paid = request.POST['is_paid']
        # is_answered = request.POST['is_answered']
        # userid = request.user.id
        ans = request.POST['ans']
      
      
        uplead = QusAndAnswer.objects.filter(id=id)
        
        uplead.update(is_paid=is_paid, 
                      is_answered=True,ans=ans)
        # messages.success(request, f"Updated Successfully")
        return redirect('/admin-panel/getfaq/')
        # return redirect(request.META.get('HTTP_REFERER', 'redirect_if_referer_not_found'))  
    else:
        getFAQ = QusAndAnswer.objects.get(id=id)    
        return render(request, "admintemp/editfaq.html", {'faq':getFAQ})




def CreateBlog(request):   
    
    catid = CategoryOfProduct.objects.all()
    if request.method == 'POST':
        fnm = request.POST['blogtitle']
        loc = request.FILES['blogimg']
        gen = request.POST['discription']
        dig = datetime.now()
        
        ulead = DailyBlogs(blogtitle=fnm,
                            blogimg=loc,
                            discription=gen,
                            date=dig,                            
                            )
        ulead.save()
        # messages.success(request, "Blog has been created successfully")
        return redirect('/admin-panel/getblog/')
    else:
        return render(request, "admintemp/addblog.html",{'category':catid})
    


def GetAllBlog(request):
    blog = DailyBlogs.objects.all().order_by('-id')
    return render(request, "admintemp/getbloglist.html", {'blogs':blog})

def UpdateBlog(request, id):
    
    uplead = DailyBlogs.objects.filter(id=id)
    uplead1 = DailyBlogs.objects.get(id=id)
    if request.method == 'POST':
        fnm = request.POST['blogtitle']
        # loc = request.FILES['blogimg'] 
        gen = request.POST['discription']
        dig = datetime.now()
             
        if len(request.FILES) !=0:
            if len(uplead1.blogimg) > 0:
                print('yessssssssssssssss1')
                os.remove(uplead1.blogimg.path)
                # print(uplead1.blogimg.path)
            uplead1.blogimg = request.FILES['blogimg']
            uplead1.save()
        
        uplead = DailyBlogs.objects.filter(id=id)
        
        uplead.update(blogtitle=fnm,
                            # blogimg=loc,
                            discription=gen,
                            date=dig,                                                      
                            )
        # messages.success(request, f"Updated Successfully")
        # return redirect('/superadmin/edit_leadinfo//')
        return redirect('/admin-panel/getblog/')  
    else:
        getBlog = DailyBlogs.objects.get(id=id)    
        return render(request, "admintemp/editbloglist.html", {'blog':getBlog})
        
        
def GetViewDailyBlogs(request, id):
    blogs = DailyBlogs.objects.get(id=id)
    # print(user)
    return render(request, "admintemp/detailblog.html",{'getblog':blogs})
    
    

def DeleteBlog(request, id):
    data = DailyBlogs.objects.get(id=id)
    data.delete()
    # messages.success(request, "Deleted succsessfull")
    return redirect('/admin-panel/getblog/')




def GetAllCustomerSupport(request):
    custsupp = CustomerSupport.objects.all().order_by('-id')
    
    paginator = Paginator(custsupp, 6)
    page_number = request.GET.get('page')
    all_lead = paginator.get_page(page_number)
    totalpage = all_lead.paginator.num_pages
    
    context = {
        'all_lead':all_lead,
        'lastpage':totalpage,
        'totalPagelist':[n+1 for n in range(totalpage)],
        'support':custsupp
    }
    return render(request, "admintemp/customersupport.html", context)

def GetViewcustomersupportprofile(request, id):
    user = CustomerSupport.objects.get(id=id)
    print(user)
    return render(request, "admintemp/userprofile.html",{'getuser':user})

def GetAllTimeSlot(request):
    slot =PoojaSlot.objects.all().order_by('-id')
    return render(request, "admintemp/slottime.html", {'slot':slot})


def CreateSlotTime(request):
    if request.method == 'POST':
        time = request.POST['timeslt']
        
        # if AnswerFAQTime.objects.filter(catname=fatime).exists():
        #         messages.info(request, 'FAQ Category is already taken')
        #         return redirect('/admin-panel/addfaqcategory/')
        # else:
        newclub = PoojaSlot(slottime=time)
        newclub.save()
        # messages.info(request, 'Time Added Successfull')
        return redirect('/admin-panel/getslottime/')
    
    else:
        return render(request, "admintemp/addslottime.html")


def UpdateSlotTime(request, id):
    # my_users = User.objects.all()
    # print(my_users)
    if request.method == 'POST':
        time = request.POST['timeslt']
        
        uplead = PoojaSlot.objects.filter(id=id)
        
        uplead.update(slottime=time)
        # messages.success(request, f"Updated Successfully")
        # return redirect('/superadmin/edit_leadinfo//')
        return redirect('/admin-panel/getslottime/')  
    else:
        getSlot = PoojaSlot.objects.get(id=id)    
        return render(request, "admintemp/editslottime.html", {'getSlot':getSlot})
    
def DeleteSlotTime(request, id):
    data = PoojaSlot.objects.get(id=id)
    data.delete()
    # messages.success(request, "Deleted succsessfull")
    return redirect('/admin-panel/getslottime/')


def PujaDetail(request, id):
    showdata =  Pooja.objects.get(id=id)
    return render(request, "admintemp/pujadetailpage.html", {'shoowdata':showdata})



def ProductDetail(request, id):
    showdata =  Products.objects.get(id=id)
    return render(request, "admintemp/productdetailpage.html", {'shoowdata':showdata})
    
    
def FamilyandFriendView(request):
    getdata = FamilyFriendsprofile.objects.all().order_by('-id')
    return render(request, "admintemp/getfamilyandfriend.html", {'getdata':getdata})

def FamilyFriendDetailPage(request, id):
    showdata =  FamilyFriendsprofile.objects.get(id=id)
    return render(request, "admintemp/famfrinddetailpage.html", {'shoowdata':showdata})


def GetViewAskByprofile(request, id):
    user = FamilyFriendsprofile.objects.get(id=id)
    print(user)
    return render(request, "admintemp/userprofile2.html",{'getuser':user})
    
    
    
def GetAllPayHistoryAsk(request):
    askpayhist = QusAndAnswerPayment.objects.all().order_by('-id')
    return render(request, "admintemp/askquspayhistory.html",{'askpayhist':askpayhist})
    
def GetViewPaymentprofile(request, id):
    user = QusAndAnswerPayment.objects.get(id=id)
    print(user)
    return render(request, "admintemp/userprofile.html",{'getuser':user})
    
    
def UpdateAskPayDetail(request, id):
    
    if request.method == 'POST':
        fnm = request.POST['status']
        
        uplead = QusAndAnswerPayment.objects.filter(id=id)
        
        uplead.update(order_status=fnm,
                           
                            )
        # messages.success(request, f"Updated Successfully")
        return redirect('/admin-panel/getaskquetionhis/')
        # return redirect(request.META.get('HTTP_REFERER', 'redirect_if_referer_not_found'))  
    else:
        getorder = QusAndAnswerPayment.objects.get(id=id)    
        return render(request, "admintemp/editaskquspayment.html", {'order':getorder})
        
        
def CreateCountryCode(request):
    if request.method == 'POST':
        cd = request.POST['code']

        
        if CountryCode.objects.filter(code=cd).first():
                messages.info(request, 'Code number is already taken')
                return redirect('/admin-panel/getcountrycode/')
        else:
            newclub = CountryCode(code=cd)
            newclub.save()
            # messages.info(request, 'Pandit Added Successfull')
        return redirect('/admin-panel/getcountrycode/')
    
    else:
        return render(request, "admintemp/createcountrycode.html")
    
def GetAllCountryCode(request):
    code = CountryCode.objects.all().order_by('-id')
    return render(request, "admintemp/getcountrycode.html", {'code':code})


def EditCountryCode(request,id):
    if request.method == 'POST':
        cd = request.POST['code']
        
        uplead = CountryCode.objects.filter(id=id)
        
        uplead.update(code=cd)
        # messages.success(request, f"Updated Successfully")
        # return redirect('/superadmin/edit_leadinfo//')
        return redirect('/admin-panel/getcountrycode/')  
    else:
        getCode = CountryCode.objects.get(id=id) 
        return render(request, "admintemp/editcountrycode.html", {'getCode':getCode})
    

def DeleteCountryCode(request, id):
    data = CountryCode.objects.get(id=id)
    data.delete()
    # messages.success(request, "Deleted succsessfull")
    return redirect('/admin-panel/getcountrycode/')
    

def AddWalletAmount(request):
    user = User.objects.get(id=request.user.id)
    print(user)
    prod = WalletAmt.objects.filter(userid=user)
    c = 0
    for i in prod:
        c = c + float(i.amount)
        # print(float(var))
        
    uss=PayByWalletAmount.objects.filter(userid_id=request.user.id).exists()

    if uss:
        var2=PayByWalletAmount.objects.get(userid_id=user)
        chg=var2.walletid
    else:
        chg=0
    
        
    print("dsdsdsd dsdsddw wewewe",prod)
    if request.method == "POST":
        user = request.user.id
        amount = request.POST['amount']
        
        
        
        var = WalletAdd(userwallet_id=user, walletamount=amount)
        var.save()
        uss=PayByWalletAmount.objects.filter(userid_id=request.user.id).exists()
        print('hcawdskj',uss)
        am = float(c)+float(amount)
        if uss:
            var2=PayByWalletAmount.objects.filter(userid_id=user)
            var2.update(walletid=am)
        else:
            var1 = PayByWalletAmount(userid_id=user, walletid=am)
            var1.save()
        
        messages.success(request, "Add wallet amount successfull..")
        return redirect('/paymentadmin/')
    return render(request, "walletamount.html", {'amount':prod, 'amt':chg})


def PaymentByRazorpay(request):
    user = User.objects.get(id=request.user.id)
    print(user)
    prod = WalletAdd.objects.filter(userwallet=user)
    print(prod[0].id)
    
    
    # pi = []
    # for i in prod:
    #     i= pi.append(i.id)
    # print("My Product", pi)
    c = 0
    for i in prod:
        c = int(i.walletamount)
        print("MJKkksdskdfsdkfsdkfsn fksdjfidskjfd", c)
    print(type(c))

    ##################################################################################################
    # RAZORPAY CODE
    ##################################################################################################
    # client = razorpay.Client(auth = (settings.razor_pay_key_id, settings.key_secret) )
    # payment = client.order.create({ 'amount': c * 100, 'currency': 'INR', 'payment_capture': 1})
    # print("******************************")
    # print(payment['amount'])
    # print("******************************")
    #
    # # pi = []
    # # for i in prod:
    # #     i= pi.append(i.askqusid)
    # # print("My Product", pi)
    #
    # prodid = prod[0].id
    # usr = request.user.id
    # date = datetime.now()
    # # quantity= request.POST['qty']
    # amount = payment['amount']/100
    # razor_pay_order_id = payment['id']
    #
    # orderobj = WalletAmt(walt_id=prodid,userid_id=usr,amount=amount,orderdate=date,razor_pay_order_id=razor_pay_order_id,order_status=True)
    # orderobj.save()

    ##################################################################################################
    # PHONEPE CODE
    ##################################################################################################
    phonepe_client = PhonePePaymentClient(merchant_id=settings.merchant_id, salt_key=settings.salt_key,
                                          salt_index=settings.salt_index, env=settings.env)
    unique_transaction_id = str(uuid.uuid4())
    ui_redirect_url = settings.redirect_base_url + reverse("wallet")
    s2s_callback_url = settings.redirect_base_url + reverse("wallet")
    amount = c * 100
    id_assigned_to_user_by_merchant = user.id
    pay_page_request = PgPayRequest.pay_page_pay_request_builder(merchant_transaction_id=unique_transaction_id,
                                                                 amount=amount,
                                                                 merchant_user_id=id_assigned_to_user_by_merchant,
                                                                 callback_url=s2s_callback_url,
                                                                 redirect_url=ui_redirect_url)
    pay_page_response = phonepe_client.pay(pay_page_request)
    print("pay_page_response ::: ", pay_page_request)
    pay_page_url = pay_page_response.data.instrument_response.redirect_info.url

    prodid = prod[0].id
    usr = request.user.id
    date = datetime.now()
    # quantity= request.POST['qty']
    amount = pay_page_request.amount / 100
    phone_pay_order_id = pay_page_response.data.merchant_transaction_id

    orderobj = WalletAmt(walt_id=prodid, userid_id=usr, amount=amount, orderdate=date,
                         razor_pay_order_id=phone_pay_order_id, order_status=True)
    orderobj.save()

    messages.success(request, 'Pay successfully.')
    # return redirect('/askquestion/'))
    return render(request, "walletcash.html", {'payment_url':pay_page_url})


# def ShowCurrentAmount(request):
#     user = User.objects.get(id=request.user.id)
#     print(user)
#     prod = WalletAmt.objects.filter(userid=user)
    
#     print(prod)
#     return render(request, "walletamount.html")
    
def PayWithWallet(request):
    user = User.objects.get(id=request.user.id)
    print(user)
    prod23 = WalletAmt.objects.filter(userid=user)
    cb = 0
    for i in prod23:
        print('i',i.amount)
        cb = cb + float(i.amount)
        
    print(cb)
    print("=================",request.user.currentaddress)
    user = User.objects.get(id=request.user.id)
    print(user)
    # addr = OrderPlaceAddress.objects.filter(userid=user)
    # print("dsfsfsfsd",addr)
    prod = Cart.objects.filter(user_id=user.id).order_by('id').reverse()
    print(prod)
    pi = []
    for i in prod:
        i= pi.append(i.product.prodname)
    print("My Product", pi) 
    c = 0
    for i in prod:
        c = c + int(i.product.price)
 
    
    ls = []
    tot = 0
    for pro in prod:
        print('Thisssssss',type(pro.product.price))
        amt = float(pro.product.price)
        qty = int(pro.quantity)
        print("wedfefefefef feff",type(amt))
        # pro = ls.append(amt)
        # qty = ls.append(qty)
        total = amt*qty
        ls.append(total)
        tot = sum(ls)
        
        print(tot)
        
        mylist = zip(prod, ls)
    

    prodid = pi
    usr = request.user.id
    date = datetime.now()
    # quantity= request.POST['qty']
    amount = tot
    razor_pay_order_id = 'Wallet'
    
    orderobj = Order(productid=prodid,userid_id=usr,orderdate=date,order_price=amount,razor_pay_order_id=razor_pay_order_id,order_status=False,address=request.user.currentaddress)
    orderobj.save()
    # # messages.success(request, "Order created....")
    
    # prod.delete()
        
    # current_user = User.objects.get(username=request.user)
    # count_cart = Cart.objects.filter(user_id=current_user.id).count()
    # return render(request, "paywithwallet.html", {'cartprod':prod, 'item':count_cart, 'totalamt':tot, 'payment':payment, 'mylist':mylist,'tot':tot, 'ggg':cb})
    upl = PayByWalletAmount.objects.get(userid_id=request.user.id)
    ll=upl.walletid
    amtminus=float(upl.walletid)-float(tot)
    uplead = PayByWalletAmount.objects.get(userid_id=request.user.id)
        
    uplead.update(walletid=str(amtminus))
    # py12=PayByWalletAmount.objects.get(id=request.user.id)
    # print('edhfcewkfjehn',py12.walletid)
    
    return render(request, "paywithwallet.html", {'ggg':cb,'cartprod':prod, 'll':ll, 'totalamt':tot, 'amtt':amtminus})
    
    # return render(request, "checkout.html")
    
def CheckoutforPuja(request):
    
    user = User.objects.get(id=request.user.id)
    print(user)
    prod1 = WalletAmt.objects.filter(userid=user)
    cb = 0
    for i in prod1:
        print('i',i.amount)
        cb = cb + float(i.amount)
        
    print(cb)
    print("=================",request.user.currentaddress)
    user = User.objects.get(id=request.user.id)
    print(user)
    addr = OrderPlaceAddress.objects.filter(userid=user)
    print("dsfsfsfsd",addr)
    prod = PujaSlotBooking.objects.filter(user_id=request.user.id).order_by('id').reverse()
    print(';kdjdhfoILejf    poewfigwel;hger;lkgkhffoksdljhairuhrepokk',prod)
    pi = []
    for i in prod:
        pi.append(i.pooja.name)
    print("My Product", pi) 
    c = 0
    for i in prod:
        c = c + int(i.pooja.price)
 
    
    ls = []
    tot = 0
    for pro in prod:
        print('Thisssssss',type(pro.pooja.price))
        amt = float(pro.pooja.price)
        # qty = int(pro.quantity)
        print("wedfefefefef feff",type(amt))
        # pro = ls.append(amt)

        
        ls.append(amt)
        tot = sum(ls)
        
        print(tot)
        
        mylist = zip(prod, ls)

    ##################################################################################################
    # RAZORPAY CODE
    ##################################################################################################
    # client = razorpay.Client(auth = (settings.razor_pay_key_id, settings.key_secret) )
    # payment = client.order.create({ 'amount': tot * 100, 'currency': 'INR', 'payment_capture': 1})
    # print("******************************")
    # print(payment)
    # print("******************************")
    #
    # prodid = pi
    # usr = request.user.id
    # date = datetime.now()
    # # quantity= request.POST['qty']
    # amount = payment['amount']/100
    # razor_pay_order_id = payment['id']
    #
    #
    # orderobj = PoojaOrder(pujaid=prodid,userid_id=usr,orderdate=date,order_price=amount,razor_pay_order_id=razor_pay_order_id,order_status=False,address=request.user.currentaddress)
    # orderobj.save()
    # messages.success(request, "Order created....")
    
    # prod.delete()
    

    # print(tot)  
    # print(ls)
    # if cb > tot:
    #     var =  cb - tot
    #     print(var)
    #     uplead = WalletAdd.objects.filter(userwallet=request.user.id)
            
    #     uplead.update(walletamount=int(var))
        
    # else:
    #     print('Invalit Amount')

    ##################################################################################################
    # PHONEPE CODE
    ##################################################################################################
    phonepe_client = PhonePePaymentClient(merchant_id=settings.merchant_id, salt_key=settings.salt_key,
                                          salt_index=settings.salt_index, env=settings.env)
    unique_transaction_id = str(uuid.uuid4())
    ui_redirect_url = settings.redirect_base_url + reverse("pujaslot_booking")
    s2s_callback_url = settings.redirect_base_url + reverse("pujaslot_booking")
    amount = int(tot) * 100
    id_assigned_to_user_by_merchant = user.id
    pay_request = PgPayRequest.pay_page_pay_request_builder(merchant_transaction_id=unique_transaction_id,
                                                            amount=amount,
                                                            merchant_user_id=id_assigned_to_user_by_merchant,
                                                            callback_url=s2s_callback_url,
                                                            redirect_url=ui_redirect_url)
    pay_puja_response = phonepe_client.pay(pay_request)
    pay_page_url = pay_puja_response.data.instrument_response.redirect_info.url

    prodid = pi
    usr = request.user.id
    date = datetime.now()
    # quantity= request.POST['qty']
    amount = pay_request.amount / 100
    phone_pay_order_id = pay_puja_response.data.merchant_transaction_id

    orderobj = PoojaOrder(pujaid=prodid,userid_id=usr,orderdate=date,order_price=amount,razor_pay_order_id=phone_pay_order_id,order_status=False,address=request.user.currentaddress)
    orderobj.save()
    
    current_user = User.objects.get(username=request.user)
    count_cart = Cart.objects.filter(user_id=current_user.id).count()
    return render(request, "checkoutforpuja.html", {'cartprod':prod, 'item':count_cart, 'totalamt':tot, 'payment_url':pay_page_url, 'mylist':mylist,'tot':tot, 'ggg':cb})
    # return render(request, "checkout.html")

def PayWithWalletforPuja(request):
    user = User.objects.get(id=request.user.id)
    print(user)
    prod23 = WalletAmt.objects.filter(userid=user)
    cb = 0
    for i in prod23:
        print('i',i.amount)
        cb = cb + float(i.amount)
        
    print(cb)
    print("=================",request.user.currentaddress)
    user = User.objects.get(id=request.user.id)
    print(user)
    # addr = OrderPlaceAddress.objects.filter(userid=user)
    # print("dsfsfsfsd",addr)
    prod = PujaSlotBooking.objects.filter(user_id=user.id).order_by('id').reverse()
    print(prod)
    pi = []
    for i in prod:
        i= pi.append(i.pooja.name)
    print("My Product", pi) 
    c = 0
    for i in prod:
        c = c + int(i.pooja.price)
 
    
    ls = []
    tot = 0
    for pro in prod:
        print('Thisssssss',type(pro.pooja.price))
        amt = float(pro.pooja.price)
        
        print("wedfefefefef feff",type(amt))
        
        ls.append(amt)
        tot = sum(ls)
        
        print(tot)
        
        mylist = zip(prod, ls)
    

    prodid = pi
    usr = request.user.id
    date = datetime.now()
    # quantity= request.POST['qty']
    amount = tot
    razor_pay_order_id = 'Wallet'
    
    orderobj = PoojaOrder(pujaid=prodid,userid_id=usr,orderdate=date,order_price=amount,razor_pay_order_id=razor_pay_order_id,order_status=False,address=request.user.currentaddress)
    orderobj.save()
    # # messages.success(request, "Order created....")
    
    # prod.delete()
        
    # current_user = User.objects.get(username=request.user)
    # count_cart = Cart.objects.filter(user_id=current_user.id).count()
    # return render(request, "paywithwallet.html", {'cartprod':prod, 'item':count_cart, 'totalamt':tot, 'payment':payment, 'mylist':mylist,'tot':tot, 'ggg':cb})
    upl = PayByWalletAmount.objects.get(userid_id=request.user.id)
    ll=upl.walletid
    amtminus=float(upl.walletid)-float(tot)
    uplead = PayByWalletAmount.objects.filter(userid_id=request.user.id)
        
    uplead.update(walletid=amtminus)
    # py12=PayByWalletAmount.objects.get(id=request.user.id)
    # print('edhfcewkfjehn',py12.walletid)
    
    return render(request, "paywithwalletforpuja.html", {'ggg':cb,'cartprod':prod, 'll':ll, 'totalamt':tot, 'amtt':amtminus})
    
    # return render(request, "checkout.html")

def CheckoutforQA(request):
    user = User.objects.get(id=request.user.id)
    print(user)
    prod1 = WalletAmt.objects.filter(userid=user)
    cb = 0
    for i in prod1:
        print('i',i.amount)
        cb = cb + float(i.amount)
        
    print(cb)
    print("=================",request.user.currentaddress)
    user = User.objects.get(id=request.user.id)
    print(user)
    addr = OrderPlaceAddress.objects.filter(userid=user)
    print("dsfsfsfsd",addr)
    prod = QusAndAnswer.objects.filter(user_id=request.user.id).order_by('id').reverse()
    print(';kdjdhfoILejf    poewfigwel;hger;lkgkhffoksdljhairuhrepokk',prod)
    pi = []
    idd=[]
    for j in prod:
        idd.append(j.id)
    print('idd',max(idd))
    for i in prod:
        pi.append(i.pooja.name)
    print("My Product", pi) 
    c = 0
    for i in prod:
        c = c + int(i.pooja.price)
    
    ls = []
    tot = 0
    for pro in prod:
        print('Thisssssss',type(pro.pooja.price))
        amt = float(pro.pooja.price)
        # qty = int(pro.quantity)
        print("wedfefefefef feff",type(amt))
        # pro = ls.append(amt)

        
        ls.append(amt)
        tot = sum(ls)
        
        print(tot)
        
        mylist = zip(prod, ls)

    ##################################################################################################
    # RAZORPAY CODE
    ##################################################################################################
    # client = razorpay.Client(auth = (settings.razor_pay_key_id, settings.key_secret) )
    # payment = client.order.create({ 'amount': tot * 100, 'currency': 'INR', 'payment_capture': 1})
    # print("******************************")
    # print(payment)
    # print("******************************")
    
    # prodid = pi
    # usr = request.user.id
    # date = datetime.now()
    # # quantity= request.POST['qty']
    # amount = payment['amount']/100
    # razor_pay_order_id = payment['id']
  
    
    # orderobj = PoojaOrder(pujaid=prodid,userid_id=usr,orderdate=date,order_price=amount,razor_pay_order_id=razor_pay_order_id,order_status=False,address=request.user.currentaddress)
    # orderobj.save()
    # messages.success(request, "Order created....")
    
    # prod.delete()
    

    # print(tot)  
    # print(ls)
    # if cb > tot:
    #     var =  cb - tot
    #     print(var)
    #     uplead = WalletAdd.objects.filter(userwallet=request.user.id)
            
    #     uplead.update(walletamount=int(var))
        
    # else:
    #     print('Invalit Amount')

    ##################################################################################################
    # PHONEPE CODE
    ##################################################################################################
    phonepe_client = PhonePePaymentClient(merchant_id=settings.merchant_id, salt_key=settings.salt_key,
                                          salt_index=settings.salt_index, env=settings.env)
    unique_transaction_id = str(uuid.uuid4())
    ui_redirect_url = settings.redirect_base_url + reverse("pujaslot_booking")
    s2s_callback_url = settings.redirect_base_url + reverse("pujaslot_booking")
    amount = int(tot) * 100
    id_assigned_to_user_by_merchant = user.id
    pay_request = PgPayRequest.pay_page_pay_request_builder(merchant_transaction_id=unique_transaction_id,
                                                            amount=amount,
                                                            merchant_user_id=id_assigned_to_user_by_merchant,
                                                            callback_url=s2s_callback_url,
                                                            redirect_url=ui_redirect_url)
    pay_pujaqa_response = phonepe_client.pay(pay_request)
    pay_page_url = pay_pujaqa_response.data.instrument_response.redirect_info.url
    
    current_user = User.objects.get(username=request.user)
    count_cart = Cart.objects.filter(user_id=current_user.id).count()
    return render(request, "checkoutforqa.html", {'cartprod':prod, 'item':count_cart, 'totalamt':tot, 'payment_url':pay_page_url, 'mylist':mylist,'tot':tot, 'ggg':cb})
    # return render(request, "checkout.html")
    
def PayWithWalletforQA(request):
    user = User.objects.get(id=request.user.id)
    print(user)
    prod23 = WalletAmt.objects.filter(userid=user)
    cb = 0
    for i in prod23:
        print('i',i.amount)
        cb = cb + float(i.amount)
        
    print(cb)
    print("=================",request.user.currentaddress)
    user = User.objects.get(id=request.user.id)
    print(user)
    # addr = OrderPlaceAddress.objects.filter(userid=user)
    # print("dsfsfsfsd",addr)
    prod = QusAndAnswer.objects.filter(userid=request.user.id).order_by('id').reverse()
    print(';kdjdhfoILejf    poewfigwel;hger;lkgkhffoksdljhairuhrepokk',prod)
    
    a=prod[0].qus
    b=prod[0].answertime.price
    c=prod[0].id
    # pi = []
    # idd=[]
    # for j in prod:
    #     idd.append(j.id)

    # print('idd',max(idd))
    # # prod = PujaSlotBooking.objects.filter(user_id=user.id).order_by('id').reverse()
    # # print(prod)
    # pi = []
    # for i in prod:
    #     pi.append(i.qus)
    # print("My Product", pi) 
    # c = 0
    # for i in prod:
    #     c = c + int(i.pooja.price)
 
    
    # ls = []
    # tot = 0
    # for pro in prod:
    #     print('Thisssssss',type(pro.pooja.price))
    #     amt = float(pro.pooja.price)
        
    #     print("wedfefefefef feff",type(amt))
        
    #     ls.append(amt)
    #     tot = sum(ls)
        
    #     print(tot)
        
    #     mylist = zip(prod, ls)
    

    # prodid = pi
    usr = request.user.id
    date = datetime.now()
    # quantity= request.POST['qty']
    amount = b
    razor_pay_order_id = 'Wallet'
    
    orderobj = QusAndAnswerPayment(askqusid_id = c,userid_id = request.user.id,orderdate = date,order_status = True,order_price = b,razor_pay_order_id = razor_pay_order_id)
    orderobj.save()
    # # messages.success(request, "Order created....")
    
    # prod.delete()
        
    # current_user = User.objects.get(username=request.user)
    # count_cart = Cart.objects.filter(user_id=current_user.id).count()
    # return render(request, "paywithwallet.html", {'cartprod':prod, 'item':count_cart, 'totalamt':tot, 'payment':payment, 'mylist':mylist,'tot':tot, 'ggg':cb})
    upl = PayByWalletAmount.objects.get(userid_id=request.user.id)
    ll=upl.walletid
    amtminus=float(upl.walletid)-float(b)
    uplead = PayByWalletAmount.objects.filter(userid_id=request.user.id)
        
    uplead.update(walletid=amtminus)
    # py12=PayByWalletAmount.objects.get(id=request.user.id)
    # print('edhfcewkfjehn',py12.walletid)
    
    return render(request, "paywithwalletforqa.html", {'ggg':cb,'cartprod':prod, 'll':ll, 'totalamt':b, 'amtt':amtminus})
    
    # return render(request, "checkout.html")
    
    
    
    
def GetAllCarts(request):
    cart = Cart.objects.all().order_by('-id')
    return render(request, "admintemp/cartlist.html", {'carts':cart})
    

def GetAllPujaCarts(request):
    cart = PujaSlotBooking.objects.all().order_by('-id')
    return render(request, "admintemp/pujacartlist.html", {'pujacarts':cart})
    