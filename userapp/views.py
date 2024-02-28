from urllib.parse import unquote
from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate,login,logout
from django.contrib.auth.hashers import make_password
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt

from accounts.models import *
from django.contrib import messages
from datetime import datetime
from adminapp.models import *
from userapp.models import *
from datetime import datetime
import razorpay
# Create your views here.
import requests
from datetime import datetime
from django.db.models import Q
from django.core.paginator import Paginator
from django.core.mail import send_mail
import uuid
from phonepe.sdk.pg.payments.v1.models.request.pg_pay_request import PgPayRequest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import json
from web_astrology import settings

# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# HELPER FUNCTION
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
def calculate_sha256_string(input_string):
    # Create a hash object using the SHA-256 algorithm
    sha256 = hashes.Hash(hashes.SHA256(), backend=default_backend())
    # Update hash with the encoded string
    sha256.update(input_string.encode('utf-8'))
    # Return the hexadecimal representation of the hash
    return sha256.finalize().hex()


# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
def base64_encode(input_dict):
    # Convert the dictionary to a JSON string
    json_data = json.dumps(input_dict)
    # Encode the JSON string to bytes
    data_bytes = json_data.encode('utf-8')
    # Perform Base64 encoding and return the result as a string
    return base64.b64encode(data_bytes).decode('utf-8')

def payment_return(transactionId):
    merchant_id = settings.merchant_id
    salt_index=settings.salt_index
    salt_key=settings.salt_key
    # form_data = request.POST
    # form_data_dict = dict(form_data)
    # transaction_id = form_data.get('transactionId', None)
    transaction_id = transactionId

    if transaction_id:
        request_url = f'https://api-preprod.phonepe.com/apis/pg-sandbox/pg/v1/status/{merchant_id}/' + transaction_id
        sha256_Pay_load_String = '/pg/v1/status/PGTESTPAYUAT/' + transaction_id + salt_key
        sha256_val = calculate_sha256_string(sha256_Pay_load_String)
        checksum = sha256_val + '###' + str(salt_index)
        headers = {
            'Content-Type': 'application/json',
            'X-VERIFY': checksum,
            'X-MERCHANT-ID': transaction_id,
            'accept': 'application/json',
        }
        response = requests.get(request_url, headers=headers)
        return response

def AddToWalletSuccessView(request):
    # Fetch transaction_id from the URL
    transaction_id = request.GET.get('transaction_id')
    prodid = request.GET.get('prodid')
    response = payment_return(transaction_id)
    res = response.json()
    if res['data']['state'] == 'COMPLETED' and transaction_id == res['data']['merchantTransactionId']:
        amount = int(res['data']['amount'])/100
        ### AddWalletAmount ###
        user = request.user.id
        qapay = QusAndAnswerPayment.objects.filter(userid=user, razor_pay_order_id='Wallet')
        prodpay = Order.objects.filter(userid=user, razor_pay_order_id='Wallet')
        pujapay = PoojaOrder.objects.filter(userid=user, razor_pay_order_id='Wallet')
        p, q, r = 0, 0, 0
        for m in qapay:
            p = p + float(m.order_price)

        for n in prodpay:
            q = q + float(n.order_price)

        for o in pujapay:
            r = r + float(o.order_price)

        z = p + q + r
        prod = WalletAmt.objects.filter(userid=user)
        c = 0
        for i in prod:
            c = c + float(i.amount)


        var = WalletAdd(userwallet_id=user, walletamount=amount)
        var.save()
        uss = PayByWalletAmount.objects.filter(userid_id=request.user.id).exists()
        am = (float(c) - float(z)) + float(amount)
        if uss:
            var2 = PayByWalletAmount.objects.filter(userid_id=user)
            var2.update(walletid=am)
        else:
            var1 = PayByWalletAmount(userid_id=user, walletid=am)
            var1.save()

        ### PaymentByRazorpay ###
        date = datetime.now()
        phone_pay_order_id = transaction_id

        orderobj = WalletAmt(walt_id=prodid, userid_id=user, amount=amount, orderdate=date,
                             razor_pay_order_id=phone_pay_order_id, order_status=True)
        orderobj.save()

        messages.success(request, "Add wallet amount successfull..")
        count_cart = Cart.objects.filter(user_id=user).count()
        count_puja = PujaSlotBooking.objects.filter(user_id=user).count()
        return render(request, "addtowalletsuccess.html",{'totalamt': amount, 'cart': count_cart, 'pooja': count_puja})
    return render(request, "addtowalletfailure.html")

def OrderSuccessView(request):
    # Fetch transaction_id from the URL
    transaction_id = request.GET.get('transaction_id')
    amount = request.GET.get('amount')
    response = payment_return(transaction_id)
    res = response.json()
    if res['data']['state'] == 'COMPLETED' and transaction_id == res['data']['merchantTransactionId']:
        user = request.user.id
        prod = Cart.objects.filter(user_id=user).order_by('id').reverse()
        pi = []
        qt = 0
        for i in prod:
            i = pi.append(i.product.prodname)
        for i in prod:
            qt += int(i.quantity)

        prodid = pi
        date = datetime.now()
        amount = int(amount)
        phone_pay_order_id = transaction_id

        # Deduct the quantity from inventory
        products_in_cart = Cart.objects.filter(user_id=user)
        for product in products_in_cart:
            prod_inventory = Products.objects.filter(id=product.product.id).first()
            prodquantity = int(prod_inventory.quantity) - int(product.quantity)
            prod_inventory.quantity = prodquantity
            prod_inventory.save()

        orderobj = Order(productid=prodid, userid_id=user, orderdate=date, order_price=amount,
                         razor_pay_order_id=phone_pay_order_id, order_status=False, address=request.user.currentaddress,
                         quantity=qt)
        orderobj.save()

        Cart.objects.filter(user_id=user).delete()
        count_cart = Cart.objects.filter(user_id=user).count()
        count_puja = PujaSlotBooking.objects.filter(user_id=user).count()
        return render(request, "ordersuccess.html", {'cart': count_cart, 'pooja': count_puja})
    return render(request, "orderfailure.html")


def BuyOrderSuccessView(request):
    # Fetch transaction_id from the URL
    transaction_id = request.GET.get('transaction_id')
    amount = request.GET.get('amount')
    product_name = request.GET.get('prod_name')
    item_quantity = request.GET.get('quantity')
    response = payment_return(transaction_id)
    res = response.json()
    if res['data']['state'] == 'COMPLETED' and transaction_id == res['data']['merchantTransactionId']:
        user = request.user.id
        productname = bytes.fromhex(product_name).decode()
        prod = Products.objects.filter(prodname=productname)
        pi = []
        qt = int(item_quantity)
        for i in prod:
            i = pi.append(i.prodname)

        # Deduct the quantity from inventory
        prod_inventory = prod.first()
        prodquantity = int(prod_inventory.quantity) - int(qt)
        prod_inventory.quantity = prodquantity
        prod_inventory.save()

        prodid = pi
        date = datetime.now()
        amount = int(amount)
        phone_pay_order_id = transaction_id

        orderobj = Order(productid=prodid, userid_id=user, orderdate=date, order_price=amount,
                         razor_pay_order_id=phone_pay_order_id, order_status=False, address=request.user.currentaddress,
                         quantity=qt)
        orderobj.save()

        count_cart = Cart.objects.filter(user_id=user).count()
        count_puja = PujaSlotBooking.objects.filter(user_id=user).count()
        return render(request, "ordersuccess.html", {'cart': count_cart, 'pooja': count_puja})
    return render(request, "orderfailure.html")


def PujaSuccessView(request):
    # Fetch transaction_id from the URL
    transaction_id = request.GET.get('transaction_id')
    amount = request.GET.get('amount')
    response = payment_return(transaction_id)
    res = response.json()
    if res['data']['state'] == 'COMPLETED' and transaction_id == res['data']['merchantTransactionId']:
        user = request.user.id
        prod = PujaSlotBooking.objects.filter(user_id=request.user.id).order_by('id').reverse()
        pi, pd = [], []
        for i in prod:
            pi.append(i.pooja.name)

        for i in prod:
            pd.append(i.dateofpuja)

        pujadate = pd
        prodid = pi
        date = datetime.now()
        phone_pay_order_id = transaction_id

        orderobj = PoojaOrder(pujaid=prodid, userid_id=user, orderdate=date, order_price=amount, bookeddate=pujadate,
                              razor_pay_order_id=phone_pay_order_id, order_status=False,
                              address=request.user.currentaddress)
        orderobj.save()

        PujaSlotBooking.objects.filter(user_id=user).delete()
        count_cart = Cart.objects.filter(user_id=user).count()
        count_puja = PujaSlotBooking.objects.filter(user_id=user).count()
        return render(request, "pujasuccess.html", {'cart': count_cart, 'pooja': count_puja})
    return render(request, "pujafailure.html")

def AskAstroSuccessView(request):
    # Fetch transaction_id from the URL
    transaction_id = request.GET.get('transaction_id')
    amount = request.GET.get('amount')
    category_id = request.GET.get('category_id')
    answer_time = request.GET.get('answer_time')
    friend = request.GET.get('friend')
    question = request.GET.get('question')
    current_date = datetime.now()
    response = payment_return(transaction_id)
    res = response.json()
    if res['data']['state'] == 'COMPLETED' and transaction_id == res['data']['merchantTransactionId']:
        user = request.user.id

        user_obj = QusAndAnswer(category_id=category_id, answertime_id=answer_time, qus=question, userid_id=user, ask_date=current_date, friend=friend)
        user_obj.save()

        prod = QusAndAnswer.objects.filter(userid=user)
        prodid = prod[len(prod) - 1].id
        phone_pay_order_id = transaction_id

        orderobj = QusAndAnswerPayment(askqusid_id=prodid, userid_id=user, orderdate=current_date, order_price=amount, razor_pay_order_id=phone_pay_order_id, order_status=True)
        orderobj.save()

        prod.update(is_paid=True)

        count_cart = Cart.objects.filter(user_id=user).count()
        count_puja = PujaSlotBooking.objects.filter(user_id=user).count()
        return render(request, "askastrosuccess.html", {'cart': count_cart, 'pooja': count_puja})
    return render(request, "askastrofailure.html")


def HomePage(request):
    bloglist = DailyBlogs.objects.all()[:3]
    horoscopecat = HoroscopeCategory.objects.all()
    try:
        horoscopecat = HoroscopeCategory.objects.all() 
        puja = Pooja.objects.all()    
        current_user = User.objects.get(username=request.user)
        count_cart = Cart.objects.filter(user_id=current_user.id).count()
        count_puja = PujaSlotBooking.objects.filter(user_id=current_user.id).count()
        return render(request, 'index.html', {'mypuja':puja, 'horoscop':horoscopecat, 'lst':bloglist,'cart':count_cart,'pooja':count_puja})
    except:
        
        return render(request, 'index.html', {'lst':bloglist, 'horoscop':horoscopecat})


def FilterHoroscopeByCategory(request,id):
    # catname = HoroscopeCategory.objects.all()
    cateid  = HoroscopeCategory.objects.get(id=id)
    print("category ", cateid)
    catfilter = Horoscope.objects.filter(horscopname=cateid)
    print("My category",catfilter)
    return render(request, "horoscope_single.html", {'catid':cateid, 'catfilter':catfilter})






# Show all Pooja with category
def OurServices(request):
    try:
        current_user = User.objects.get(username=request.user)
        count_cart = Cart.objects.filter(user_id=current_user.id).count()
        count_puja = PujaSlotBooking.objects.filter(user_id=current_user.id).count()
        catname = CategoryOfPooja.objects.all()
        catname1=[]
        for i in catname:
             if i.active_status:
                 catname1.append(i)
             else:
                 continue
        print('dskfmnaSKdfmadfm',catname1)
        pojadetail = Pooja.objects.all()
        catfilter1=[]
        for i in pojadetail:
             if i.category.active_status:
                 if i.active_status:
                    catfilter1.append(i)
             else:
                 continue
        print('dskfmnaSKdfmadfm',catfilter1)
        lst = []
        for lr in catname:
            # for rl in prodnm:
                procat = Pooja.objects.filter(category=lr.id).count()
                lst.append(procat)
        print('wsdssssssdfdfdfgrtgrrrhthhr', lst)
        
        mylist = zip(catname1, lst)
        
        if 'q' in request.GET:
            q = request.GET['q']
            # data = Data.objects.filter(last_name__icontains=q)
            multiple_q = Q(Q(name__contains=q) | Q(discription__contains=q) | Q(advantages__contains=q) | Q(category__catname__contains=q) | Q(price__contains=q))
            data = Pooja.objects.filter(multiple_q)
            
            # print("ewfweewdfewew  :fwfw", data[0].email)
            context = {
                'data': data,
                'cart':count_cart,
                'pooja':count_puja,
                'mylist':mylist
            }
            return render(request, "search-puja.html",context)
        
        paginator = Paginator(catfilter1, 6)
        page_number = request.GET.get('page')
        all_lead = paginator.get_page(page_number)
        totalpage = all_lead.paginator.num_pages
        
        context = {
            'all_lead':all_lead,
            'lastpage':totalpage,
            'totalPagelist':[n+1 for n in range(totalpage)],
            'catname':catname1, 
            'puja':catfilter1,
            'cart':count_cart,
            'pooja':count_puja,
            'mylist':mylist
        }
        return render(request, 'service_single.html', context)
    except:
        catname = CategoryOfPooja.objects.all()
        catname1=[]
        for i in catname:
             if i.active_status:
                 catname1.append(i)
             else:
                 continue
        print('dskfmnaSKdfmadfm',catname1)
        pojadetail = Pooja.objects.all()
        catfilter1=[]
        for i in pojadetail:
             if i.category.active_status:
                 if i.active_status:
                    catfilter1.append(i)
             else:
                 continue
        print('dskfmnaSKdfmadfm',catfilter1)
        lst = []
        for lr in catname:
            # for rl in prodnm:
                procat = Pooja.objects.filter(category=lr.id).count()
                lst.append(procat)
        print('wsdssssssdfdfdfgrtgrrrhthhr', lst)
        
        mylist = zip(catname1, lst)
        
        if 'q' in request.GET:
            q = request.GET['q']
            # data = Data.objects.filter(last_name__icontains=q)
            multiple_q = Q(Q(name__contains=q) | Q(discription__contains=q) | Q(advantages__contains=q) | Q(category__catname__contains=q) | Q(price__contains=q))
            data = Pooja.objects.filter(multiple_q)
            
            # print("ewfweewdfewew  :fwfw", data[0].email)
            context = {
                'data': data,
                'mylist':mylist
            }
            return render(request, "search-puja.html",context)
        
        paginator = Paginator(catfilter1, 6)
        page_number = request.GET.get('page')
        all_lead = paginator.get_page(page_number)
        totalpage = all_lead.paginator.num_pages
        
        context = {
            'all_lead':all_lead,
            'lastpage':totalpage,
            'totalPagelist':[n+1 for n in range(totalpage)],
            'catname':catname1, 
            'puja':catfilter1,
            'mylist':mylist
        }
        return render(request, 'service_single.html', context)
        
# Filter Pooja By category
def FilterByCategory(request,id):
    try:
        current_user = User.objects.get(username=request.user)
        count_cart = Cart.objects.filter(user_id=current_user.id).count()
        count_puja = PujaSlotBooking.objects.filter(user_id=current_user.id).count()
        catname = CategoryOfPooja.objects.all()
        cateid  = CategoryOfPooja.objects.get(id=id)
        print(cateid)
        catname1=[]
        for i in catname:
             if i.active_status:
                 catname1.append(i)
             else:
                 continue
        print('dskfmnaSKdfmadfm',catname1)
        catfilter = Pooja.objects.filter(category=cateid)
        catfilter1=[]
        for i in catfilter:
             if i.category.active_status:
                 if i.active_status:
                    catfilter1.append(i)
             else:
                 continue
        print('dskfmnaSKdfmadfm',catfilter1)
        print("My category",catfilter)
        lst = []
        for lr in catname:
            # for rl in prodnm:
                procat = Pooja.objects.filter(category=lr.id).count()
                lst.append(procat)
        print('wsdssssssdfdfdfgrtgrrrhthhr', lst)
        
        mylist = zip(catname1, lst)
        return render(request, "service_single.html", {'catid':cateid, 'catfilter':catfilter1, 'catname':catname1,'cart':count_cart,'pooja':count_puja,'mylist':mylist})
    except:
        catname = CategoryOfPooja.objects.all()
        cateid  = CategoryOfPooja.objects.get(id=id)
        print(cateid)
        catname1=[]
        for i in catname:
             if i.active_status:
                 catname1.append(i)
             else:
                 continue
        print('dskfmnaSKdfmadfm',catname1)
        catfilter = Pooja.objects.filter(category=cateid)
        catfilter1=[]
        for i in catfilter:
             if i.category.active_status:
                 if i.active_status:
                    catfilter1.append(i)
             else:
                 continue
        print('dskfmnaSKdfmadfm',catfilter1)
        print("My category",catfilter)
        lst = []
        for lr in catname:
            # for rl in prodnm:
                procat = Pooja.objects.filter(category=lr.id).count()
                lst.append(procat)
        print('wsdssssssdfdfdfgrtgrrrhthhr', lst)
        
        mylist = zip(catname1, lst)
        return render(request, "service_single.html", {'catid':cateid, 'catfilter':catfilter1, 'catname':catname1,'mylist':mylist})
        
        
        
        
        
# Show all Product with category
def OurProducts(request):
    try:
        current_user = User.objects.get(username=request.user)
        count_cart = Cart.objects.filter(user_id=current_user.id).count()
        count_puja = PujaSlotBooking.objects.filter(user_id=current_user.id).count()
        catname = CategoryOfProduct.objects.all()
        
        catname1=[]
        for i in catname:
             if i.active_status:
                 catname1.append(i)
             else:
                 continue
        print('dskfmnaSKdfmadfm',catname1)
        proddetail = Products.objects.all()
        proddetail1=[]
        for i in proddetail:
             if i.category.active_status:
                 if i.active_status:
                    proddetail1.append(i)
             else:
                 continue
        print('dskfmnaSKdfmadfm',proddetail1)
        
        lst = []
        for lr in catname:
            # for rl in prodnm:
                procat = Products.objects.filter(category=lr.id).count()
                lst.append(procat)
        print('wsdssssssdfdfdfgrtgrrrhthhr', lst)
        
        mylist = zip(catname1, lst)
        
        
        if 'q' in request.GET:
            q = request.GET['q']
            # data = Data.objects.filter(last_name__icontains=q)
            multiple_q = Q(Q(prodname__contains=q) | Q(discription__contains=q) | Q(price__contains=q) | Q(category__catprod__contains=q) | Q(offers__contains=q))
            data = Products.objects.filter(multiple_q)
            
            # print("ewfweewdfewew  :fwfw", data[0].email)
            context = {
                'data': data,
                'cart':count_cart,
                'pooja':count_puja,
                'mylist':mylist
            }
            return render(request, "search-product.html",context)
        
        paginator = Paginator(proddetail1, 6)
        print(paginator)
        page_number = request.GET.get('page')
        all_lead = paginator.get_page(page_number)
        print(">>>>>>>>",all_lead)
        totalpage = all_lead.paginator.num_pages
        # for i in all_lead:
        #     print(i)
        context = {
            'all_lead':all_lead,
            'lastpage':totalpage,
            'totalPagelist':[n+1 for n in range(totalpage)],
            'catname':catname1, 
            'product':proddetail1,
            'cart':count_cart,
            'pooja':count_puja,
            'mylist':mylist
        }
        return render(request, 'product.html', context)
    except:
        catname = CategoryOfProduct.objects.all()
        catname1=[]
        for i in catname:
             if i.active_status:
                 catname1.append(i)
             else:
                 continue
        print('dskfmnaSKdfmadfm',catname1)
        proddetail = Products.objects.all()
        proddetail1=[]
        for i in proddetail:
             if i.category.active_status:
                 if i.active_status:
                    proddetail1.append(i)
             else:
                 continue
        print('dskfmnaSKdfmadfm',proddetail1)
        lst = []
        for lr in catname:
            # for rl in prodnm:
                procat = Products.objects.filter(category=lr.id).count()
                lst.append(procat)
        print('wsdssssssdfdfdfgrtgrrrhthhr', lst)
        
        mylist = zip(catname1, lst)
        
        if 'q' in request.GET:
            q = request.GET['q']
            # data = Data.objects.filter(last_name__icontains=q)
            multiple_q = Q(Q(prodname__contains=q) | Q(discription__contains=q) | Q(price__contains=q) | Q(category__catprod__contains=q) | Q(offers__contains=q))
            data = Products.objects.filter(multiple_q)
            
            # print("ewfweewdfewew  :fwfw", data[0].email)
            context = {
                'data': data,
                
                'mylist':mylist
            }
            return render(request, "search-product.html",context)
        
        paginator = Paginator(proddetail1, 6)
        print(paginator)
        page_number = request.GET.get('page')
        all_lead = paginator.get_page(page_number)
        print(">>>>>>>>",all_lead)
        totalpage = all_lead.paginator.num_pages
        # for i in all_lead:
        #     print(i)
        context = {
            'all_lead':all_lead,
            'lastpage':totalpage,
            'totalPagelist':[n+1 for n in range(totalpage)],
            'catname':catname1, 
            'product':proddetail1,
            'mylist':mylist
        }
        return render(request, 'product.html', context)
# Filter Product By category
def FilterProductByCategory(request,id):
    try:
        current_user = User.objects.get(username=request.user)
        count_cart = Cart.objects.filter(user_id=current_user.id).count()
        count_puja = PujaSlotBooking.objects.filter(user_id=current_user.id).count()
        
        catname = CategoryOfProduct.objects.all()
        # prodnm = Products.objects.all()
        cateid  = CategoryOfProduct.objects.get(id=id)
        print(cateid)
        catfilter = Products.objects.filter(category=cateid)
        for i in catfilter:
            print(i.prodname)
        catname1=[]
        for i in catname:
             if i.active_status:
                 catname1.append(i)
             else:
                 continue
        print('dskfmnaSKdfmadfm',catname1)
        catfilter1=[]
        for i in catfilter:
             if i.category.active_status:
                 if i.active_status:
                    catfilter1.append(i)
             else:
                 continue
        print('dskfmnaSKdfmadfm',catfilter1)
        print("My category",catfilter)
        lst = []
        for lr in catname:
            # for rl in prodnm:
                procat = Products.objects.filter(category=lr.id).count()
                lst.append(procat)
        print('wsdssssssdfdfdfgrtgrrrhthhr', lst)
        mylist = zip(catname1, lst)
        return render(request, "product.html", {'catid':cateid, 'catfilter':catfilter1, 'catname':catname1,'cart':count_cart,'pooja':count_puja,'mylist':mylist})
    except:
        catname = CategoryOfProduct.objects.all()
        # prodnm = Products.objects.all()
        cateid  = CategoryOfProduct.objects.get(id=id)
        print(cateid)
        catfilter = Products.objects.filter(category=cateid)
        for i in catfilter:
            print(i.prodname)
        catname1=[]
        for i in catname:
             if i.active_status:
                 catname1.append(i)
             else:
                 continue
        print('dskfmnaSKdfmadfm',catname1)
        catfilter1=[]
        for i in catfilter:
             if i.category.active_status:
                 if i.active_status:
                    catfilter1.append(i)
             else:
                 continue
        print('dskfmnaSKdfmadfm',catfilter1)
        print("My category",catfilter)
        lst = []
        for lr in catname:
            # for rl in prodnm:
                procat = Products.objects.filter(category=lr.id).count()
                lst.append(procat)
        print('wsdssssssdfdfdfgrtgrrrhthhr', lst)
        mylist = zip(catname1, lst)
        return render(request, "product.html", {'catid':cateid, 'catfilter':catfilter1, 'catname':catname1,'mylist':mylist})

def ViewProductDetail(request,id):
    try:
        # current_user = User.objects.get(username=request.user)
        # count_cart = Cart.objects.filter(user_id=current_user.id).count()
        # count_puja = PujaSlotBooking.objects.filter(user_id=current_user.id).count()
        # prod = Products.objects.get(id=id)
        # print(prod)
        # return render(request, "productdetail.html", {'detailprod':prod,'cart':count_cart,'pooja':count_puja})
        current_user = User.objects.get(username=request.user)
        count_cart = Cart.objects.filter(user_id=current_user.id).count()
        count_puja = PujaSlotBooking.objects.filter(user_id=current_user.id).count()
        prod = Products.objects.get(id=id)
        print(prod.price)
        print(prod.offers)
        caloffer=(float(prod.price)*float(prod.offers))/100
        cal=float(prod.price)-caloffer
        prodquan=int(prod.quantity)
        ob = Products.objects.filter(id=id)
        ob.update(offerprice=cal)
        faq = Faq.objects.filter(product=prod)
        sku = None
        if prod.sku:
            sku = Products.objects.filter(sku=prod.sku)
        return render(request, "productdetail.html", {'detailprod':prod,'cart':count_cart,'pooja':count_puja,'cal':cal, 'prodquan':prodquan, 'faq_items': faq, 'sku': sku})
    except User.DoesNotExist:
        prod = Products.objects.get(id=id)
        print(prod)
        print(prod.price)
        print(prod.offers)
        caloffer=(float(prod.price)*float(prod.offers))/100
        cal=float(prod.price)-caloffer
        prodquan=int(prod.quantity)
        faq = Faq.objects.filter(product=prod)
        return render(request, "productdetail.html", {'detailprod':prod,'cal':cal, 'prodquan':prodquan, 'faq_items': faq})


# def ViewPujaDetail(request, id):
#     current_user = User.objects.get(username=request.user)
#     count_cart = Cart.objects.filter(user_id=current_user.id).count()
#     count_puja = PujaSlotBooking.objects.filter(user_id=current_user.id).count()
#     poja = Pooja.objects.get(id=id)
#     print(poja)
#     caloffer=(float(poja.price)*float(poja.offers))/100
#     cal=float(poja.price)-caloffer
#     slottime = PoojaSlot.objects.all()
#     return render(request, "pujadetail.html", {'detailpoja':poja,'slot':slottime,'cart':count_cart,'pooja':count_puja, 'cal':cal})

def ViewPujaDetail(request, id):
    try:
        current_user = User.objects.get(username=request.user)
        count_cart = Cart.objects.filter(user_id=current_user.id).count()
        count_puja = PujaSlotBooking.objects.filter(user_id=current_user.id).count()
        prod = Pooja.objects.get(id=id)
        print(prod.price)
        print(prod.offers)
        caloffer=(float(prod.price)*float(prod.offers))/100
        cal=float(prod.price)-caloffer
        slottime = PoojaSlot.objects.all()
        ob = Pooja.objects.filter(id=id)
        ob.update(offerprice=cal)
        faq = Faq.objects.filter(pooja=prod)
        return render(request, "pujadetail.html", {'detailpoja':prod,'slot':slottime,'cart':count_cart,'pooja':count_puja,'cal':cal, 'faq_items': faq})
    except User.DoesNotExist:
        poja = Pooja.objects.get(id=id)
        print(poja)
        slottime = PoojaSlot.objects.all()
        faq = Faq.objects.filter(pooja=poja)
        return render(request, "pujadetail.html", {'detailpoja':poja,'slot':slottime, 'faq_items': faq})

# def AddPoojaSlot(request, id):
#     try:
#         user = User.objects.get(username=request.user)    #current user access anywhere
#         obj = Pooja.objects.get(id=id)
        
#         c = PujaSlotBooking(user=user, pooja=obj)
#         c.save()
#         #(request, "Puja slot booked successfully...  ")
#         return redirect(request.META.get('HTTP_REFERER', 'redirect_if_referer_not_found')) 
#     except:
#         return redirect('/login/')
#         # #(request, "Puja slot already booked!!!")
#         # return redirect(request.META.get('HTTP_REFERER', 'redirect_if_referer_not_found')) 
        
        
def AddPoojaSlot(request, id):
    # print('gazskdhgi;sudghaordgjtsegvofdigjodfojgljgjdfdgodfodfoiohgidifihoig',str(request.user))
    # if str(request.user)=='AnonymousUser':
    #     return redirect('/login/')
    # else:
    try:
        
        
        user = User.objects.get(username=request.user)    #current user access anywhere
        obj = Pooja.objects.get(id=id)
        print('ksdhbchjk',user)
        print('jhdbch   ',obj)
        if request.method =="POST":
            user=request.user
            slot = request.POST['pujaslt']
            date = request.POST['date']
            pujaid = obj

            if PujaSlotBooking.objects.filter(user=user,pooja=pujaid).first():
                messages.info(request, 'Puja slot is already booked')
                return redirect(request.META.get('HTTP_REFERER', 'redirect_if_referer_not_found')) 
            
            c = PujaSlotBooking(user=user, pooja=pujaid, pujaslot_id=slot, dateofpuja=date)
            c.save()
            messages.success(request, "You have successfully added puja in your cart.")
            return redirect(request.META.get('HTTP_REFERER', 'redirect_if_referer_not_found'))        
            
        else:
            # (request, "Puja slot already booked")
            return redirect(request.META.get('HTTP_REFERER', 'redirect_if_referer_not_found'))    
    except User.DoesNotExist:
        return redirect(f'/login/?next=/puja-detail/{id}/')
    # else:
    #     user=request.user
    #     slot = request.POST['pujaslt']
    #     date = request.POST['date']
    #     pujaid = request.POST['pujaid']

    #     c = PujaSlotBooking(user=user, pooja=pujaid, pujaslot=slot, dateofpuja=date)
    #     c.save()
    #     #(request, "Puja slot booked successfully...  ")
    #     print('jdkvje')
    #     #(request, "Something right!!!!!!!!")
    #     return redirect(request.META.get('HTTP_REFERER', 'redirect_if_referer_not_found')) 
    #     print('difvujfnveq')
    #     #(request, "Something wrong!!!!!!!!")
    #     return redirect(request.META.get('HTTP_REFERER', 'redirect_if_referer_not_found'))
  
        # return redirect('/login/')
        # #(request, "Puja slot already booked!!!")
        # return redirect(request.META.get('HTTP_REFERER', 'redirect_if_referer_not_found')) 

def ViewPujadescription(request, id):
    current_user = User.objects.get(username=request.user)
    countcart = Cart.objects.filter(user_id=current_user.id).count()
    count_puja = PujaSlotBooking.objects.filter(user_id=current_user.id).count()
    detailprod = PujaSlotBooking.objects.get(id=id)
    print("YYUUHJJJJ HHJKJK",detailprod.pooja.price)
    return render(request, "pujadetailbyslot.html",{'detailprod':detailprod,'cart':countcart,'pooja':count_puja})

def ViewPujaSlotBooking(request):
    try:
        current_user = User.objects.get(username=request.user)
        countcart = Cart.objects.filter(user_id=current_user.id).count()
        count_puja = PujaSlotBooking.objects.filter(user_id=current_user.id).count()
        
        user = User.objects.get(id=request.user.id)
        print(user)
        prod = PujaSlotBooking.objects.filter(user_id=user.id).order_by('id').reverse()
        print("ddferfe fefefefe rfer",prod)
        pi = []
        for i in prod:
            i= pi.append(i.pooja.name)
        print("My Product", pi) 
        c = 0
        g = 0
        for i in prod:
            c = c + int(i.pooja.price)
            g = g + float(i.pooja.offerprice)
        print(c)

        ##################################################################################################
        # RAZORPAY CODE
        ##################################################################################################
        # client = razorpay.Client(auth = (settings.razor_pay_key_id, settings.key_secret) )
        # payment = client.order.create({ 'amount': g * 100, 'currency': 'INR', 'payment_capture': 1})
        # print("******************************")
        # print(payment)
        # print("******************************")
        #
        # pujaid = pi
        # usr = request.user.id
        # date = datetime.now()
        # # quantity= request.POST['qty']
        # amount = payment['amount']/100
        # razor_pay_order_id = payment['id']
        #
        # # orderobj = PoojaOrder(pujaid=pujaid,userid_id=usr,orderdate=date,order_price=amount,razor_pay_order_id=razor_pay_order_id,order_status=False)
        # # orderobj.save()
        # # #(request, "Order created....")

        ##################################################################################################
        # PHONEPE CODE
        ##################################################################################################
        unique_transaction_id = str(uuid.uuid4())
        ui_redirect_url = settings.redirect_base_url + reverse("pujaslot_booking")
        s2s_callback_url = settings.redirect_base_url + reverse("pujaslot_booking")
        amount = int(g) * 100
        id_assigned_to_user_by_merchant = user.id
        pay_request = PgPayRequest.pay_page_pay_request_builder(merchant_transaction_id=unique_transaction_id,
                                                                amount=amount,
                                                                merchant_user_id=id_assigned_to_user_by_merchant,
                                                                callback_url=s2s_callback_url,
                                                                redirect_url=ui_redirect_url)
        pay_page_response = settings.phonepe_client.pay(pay_request)
        pay_page_url = pay_page_response.data.instrument_response.redirect_info.url
            
        
        current_user = User.objects.get(username=request.user)
        # count_cart = Cart.objects.filter(user_id=current_user.id).count()
        count_cart = PujaSlotBooking.objects.filter(user_id=current_user.id)
    	# pujaslot = models.ForeignKey(PoojaSlot, on_delete=models.CASCADE)
        print('count_cart',count_cart[0].pujaslot)
        # return render(request, "showpujaslot.html", {'cartprod':prod, 'item':count_cart, 'totzalamt':c, 'payment':payment})
        return render(request, "showpujaslot.html", {'cartprod':prod, 'slot':count_cart[0].pujaslot,'slot1':count_cart[0].dateofpuja,'totalamt':c, 'totalamt1':g, 'payment_url':pay_page_url,'cart':countcart,'pooja':count_puja})
    except:
        return render(request, 'showpujaslot.html', {'cart':countcart,'pooja':count_puja})
        
        
        
        
    
    
# def AddToCart(request, id):
    
#     # print(user)
#     # print(obj)
#     try:
#         user = User.objects.get(username=request.user)    #current user access anywhere
#         obj = Products.objects.get(id=id)
#         if request.method=='POST':
#             qty=request.POST['quantity']
            
#             if Cart.objects.filter(user=user,product=obj).exists():
#                 messages.info(request, 'Puja slot is already booked')
#                 return redirect(request.META.get('HTTP_REFERER', 'redirect_if_referer_not_found')) 
        
#             c = Cart(user=user, product=obj,quantity=qty)
#             c.save()
#             #(request, "Cart create successfully...  ")
#             return redirect(request.META.get('HTTP_REFERER', 'redirect_if_referer_not_found')) 
        
#         else:
#             #(request, "Something went wrong!")
#             return redirect(request.META.get('HTTP_REFERER', 'redirect_if_referer_not_found'))    
#     except User.DoesNotExist:
#              return redirect('/login/')


        # #(request, "Cart already created!!!")
        # return redirect(request.META.get('HTTP_REFERER', 'redirect_if_referer_not_found')) 




def AddToCart(request, id):
    # print(user)
    # print(obj)
    try:
        current_user = User.objects.get(username=request.user)
        countcart = Cart.objects.filter(user_id=current_user.id).count()
        count_puja = PujaSlotBooking.objects.filter(user_id=current_user.id).count()
        user = User.objects.get(username=request.user)    #current user access anywhere
        obj = Products.objects.get(id=id)
        print('obj.quantity',obj.quantity)
        if request.method=='POST':
            qty=request.POST['quan']
            if Cart.objects.filter(user=user,product=obj).exists():
                # messages.info(request, 'Puja slot is already booked')
                return redirect(request.META.get('HTTP_REFERER', 'redirect_if_referer_not_found'))
            print('qty',qty)
            c = Cart(user=user, product=obj,quantity=qty)
            c.save()
            # Shifted to Payment checkout section, After payment is completed the inventory quantity will deduct
            # prodquantity=int(obj.quantity)-int(qty)
            # print(prodquantity)
            # obj1 = Products.objects.filter(id=id)
            # obj1.update(quantity=prodquantity)
            # messages.success(request, "Cart create successfully...  ")
            return redirect(request.META.get('HTTP_REFERER', 'redirect_if_referer_not_found'),{'cart':countcart,'pooja':count_puja})
        else:
            messages.success(request, "Something went wrong!")
            return redirect(request.META.get('HTTP_REFERER', 'redirect_if_referer_not_found'))
    except User.DoesNotExist:
             return redirect(f'/login/?next=/product-detail/{id}/')
        # messages.success(request, "Cart already created!!!")
        # return redirect(request.META.get('HTTP_REFERER', 'redirect_if_referer_not_found'))
        
        
        
def ViewProductdescription(request, id):
    current_user = User.objects.get(username=request.user)
    countcart = Cart.objects.filter(user_id=current_user.id).count()
    count_puja = PujaSlotBooking.objects.filter(user_id=current_user.id).count()
    if request.method == 'POST':
        qty=request.POST['quan']
        
        uplead = Cart.objects.filter(id=id)
        
        uplead.update(quantity=qty)
        messages.success(request, f"Updated Successfully")
        # return redirect('/superadmin/edit_leadinfo//')
        return redirect('/view-cart/')
    else:
        detailprod = Cart.objects.get(id=id)
        print("YYUUHJJJJ HHJKJK",detailprod.product.price)
        
        caloffer=(float(detailprod.product.price)*float(detailprod.product.offers))/100
        cal=float(detailprod.product.price)-caloffer
        prodquan=int(detailprod.product.quantity)   
        
        return render(request, "productdetailbycart.html",{'detailprod':detailprod,'cal':cal, 'prodquan':prodquan, 'cart':countcart,'pooja':count_puja})

# def ViewCartProduct(request):
#     try:
#         user = User.objects.get(id=request.user.id)
#         print(user)
#         prod = Cart.objects.filter(user_id=user.id).order_by('id').reverse()
#         print(prod)
#         pi = []
#         for i in prod:
#             i= pi.append(i.product.prodname)
#         print("My Product", pi) 
#         c = 0
#         for i in prod:
#             c = c + int(i.product.price)
#         print(c)   
        
        
#         ls = []
#         tot = 0
#         for pro in prod:
#             print('Thisssssss',type(pro.product.price))
#             amt = float(pro.product.price)
#             qty = int(pro.quantity)
#             print("wedfefefefef feff",type(amt))
#             # pro = ls.append(amt)
#             # qty = ls.append(qty)
#             total = amt*qty
#             ls.append(total)
#             tot = sum(ls)
            
#             print(tot)
            
#             mylist = zip(prod, ls)
        
#         # client = razorpay.Client(auth = (settings.razor_pay_key_id, settings.key_secret) )
#         # payment = client.order.create({ 'amount': tot * 100, 'currency': 'INR', 'payment_capture': 1})
#         # print("******************************")
#         # print(payment)
#         # print("******************************")
        
#         # prodid = pi
#         # usr = request.user.id
#         # date = datetime.now()
#         # # quantity= request.POST['qty']
#         # amount = payment['amount']/100
#         # razor_pay_order_id = payment['id']
        
#         # orderobj = Order(productid=prodid,userid_id=usr,orderdate=date,order_price=amount,razor_pay_order_id=razor_pay_order_id,order_status=False)
#         # orderobj.save()
#         # # #(request, "Order created....")
            
        
     
#         # print(tot)  
#         # print(ls)
        
#         current_user = User.objects.get(username=request.user)
#         count_cart = Cart.objects.filter(user_id=current_user.id).count()
#         return render(request, "showcart.html", {'cartprod':prod, 'item':count_cart, 'totalamt':c, 'mylist':mylist,'tot':tot})
#     except:
#         return render(request, 'showcart.html')

@csrf_exempt
def UpdateCartProduct(request):
    if request.method == 'POST':
        user = User.objects.get(id=request.user.id)
        data = json.loads(request.body)
        # Access the values
        quantity = data.get('quantity')
        product_id = data.get('product_id')
        prod = Cart.objects.filter(user_id=user.id, product=product_id).first()
        if not prod:
            return JsonResponse({'message': 'Data Not Found!'}, status=404)
        prod.quantity = quantity
        prod.save()
        return JsonResponse({'message': 'Cart updated successfully'})


def ViewCartProduct(request):
    try:
        current_user = User.objects.get(username=request.user)
        countcart = Cart.objects.filter(user_id=current_user.id).count()
        count_puja = PujaSlotBooking.objects.filter(user_id=current_user.id).count()
        
        user = User.objects.get(id=request.user.id)
        print(user)
        prod = Cart.objects.filter(user_id=user.id).order_by('id').reverse()
        print(prod)
        pi = []
        for i in prod:
            i= pi.append(i.product.prodname)
        print("My Product", pi) 
        print('[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]')
        c = 0
        for i in prod:
            c = c + float(i.product.offerprice)
        print('======================',c)   
        
        
        
        ls = []
        tot = 0
        for pro in prod:
            print('Thisssssss',type(pro.product.offerprice))
            amt = float(pro.product.offerprice)
            qty = int(pro.quantity)
            print("wedfefefefef feff",type(amt))
            # pro = ls.append(amt)
            # qty = ls.append(qty)
            total = amt*qty
            ls.append(total)
            tot = sum(ls)
            
            print(tot)
            
            mylist = zip(prod, ls)
        
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
        
        # orderobj = Order(productid=prodid,userid_id=usr,orderdate=date,order_price=amount,razor_pay_order_id=razor_pay_order_id,order_status=False)
        # orderobj.save()
        # # #(request, "Order created....")
            
        
     
        # print(tot)  
        # print(ls)
        
        current_user = User.objects.get(username=request.user)
        count_cart = Cart.objects.filter(user_id=current_user.id).count()
        return render(request, "showcart.html", {'cartprod':prod, 'item':count_cart, 'totalamt':c, 'mylist':mylist,'tot':tot,'cart':countcart,'pooja':count_puja})
    except:
        return render(request, 'showcart.html', {'cart':countcart,'pooja':count_puja})
        
        
        

def OrderPlaceAddres(request):
    #-===================================
    item_name = request.GET.get('item_name', None)
    item_quantity = request.GET.get('quantity', None)
    prod = None
    if item_name:
        prod = Products.objects.filter(prodname=item_name).first()
        if not prod:
            messages.error(request, 'Item not Found.')
            return redirect('/products/')
    current_user = User.objects.get(username=request.user)
    countcart = Cart.objects.filter(user_id=current_user.id).count()
    count_puja = PujaSlotBooking.objects.filter(user_id=current_user.id).count()
    if not countcart and not item_name:
        messages.error(request, 'Cart is Empty.')
        return redirect('/view-cart/')

    if request.method == 'POST':
        addre = request.POST['address']
        mobileno = request.POST['mobileno']
        houseno = request.POST['houseno']
        area = request.POST['area']
        landmark = request.POST['landmark']
        pincode = request.POST['pincode']
        towncity = request.POST['towncity']
        state = request.POST['state']
        usr  = request.user.id

        uplead = User.objects.filter(id=usr)

        uplead.update(currentaddress=addre,mobileno=mobileno,
                      houseno=houseno,area=area,landmark=landmark,pincode=pincode,
                      towncity=towncity, state=state)
        # orderobj.save()
        if item_name and prod:
            caloffer = (float(prod.price) * float(prod.offers)) / 100
            cal = float(prod.price) - caloffer
            # Shifted to Payment checkout section, After payment is completed the inventory quantity will deduct
            # prodquantity = int(prod.quantity) - int(item_quantity)
            # prod.quantity = prodquantity
            # prod.save()
            context = {"id":prod.id, "prodname": prod.prodname, 'price': cal*int(item_quantity), 'quantity': item_quantity}
            request.session['context'] = context
            return redirect('/product/checkout/')
        return redirect('/cart/checkout/')

    else:
        usr  = request.user.id
        getUser = User.objects.get(id=usr)
        # uplead = User.objects.filter(id=usr)
    return render(request, "orderaddress.html",{'getUser':getUser,'cart':countcart,'pooja':count_puja})
    

def BuyNow(request):
    current_user = User.objects.get(username=request.user)
    countcart = Cart.objects.filter(user_id=current_user.id).count()
    count_puja = PujaSlotBooking.objects.filter(user_id=current_user.id).count()
    user = User.objects.get(id=request.user.id)
    prod11 = PayByWalletAmount.objects.get(userid=user)
    cb = prod11.walletid

    context = request.session['context']
    prod_id = context['id'] or None
    prod_name = context['prodname'] or None
    prod_price = context['price'] or None
    item_quantity = context['quantity'] or None
    prod = Products.objects.filter(id=int(prod_id)).first()
    if not prod:
        messages.error(request, 'Item not Found.')
        return redirect('/products/')

    # if float(cb)>=float(tot):

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
    # # address = addr.address
    #
    # orderobj = Order(productid=prodid,userid_id=usr,orderdate=date,order_price=amount,razor_pay_order_id=razor_pay_order_id,order_status=False,address=request.user.currentaddress,quantity=qt)
    # orderobj.save()
    # messages.success(request, "Order created....")

    # After Checkout cart will 0
    # prod.delete()

    ##################################################################################################
    # PHONEPE CODE
    ##################################################################################################
    unique_transaction_id = str(uuid.uuid4())
    decoded_prod_name = unquote(prod_name).encode().hex()
    redirect_url = settings.redirect_base_url + reverse("buy_now_success") + f'?transaction_id={unique_transaction_id}&prod_name={decoded_prod_name}&amount={int(prod_price)}&quantity={item_quantity}'
    callback_url = settings.redirect_base_url + reverse("buy_now_success") + f'?transaction_id={unique_transaction_id}&prod_name={decoded_prod_name}&amount={int(prod_price)}&quantity={item_quantity}'
    amount = int(prod_price) * 100
    id_assigned_to_user_by_merchant = user.id
    pay_request = PgPayRequest.pay_page_pay_request_builder(merchant_transaction_id=unique_transaction_id,
                                                            amount=amount,
                                                            merchant_user_id=id_assigned_to_user_by_merchant,
                                                            callback_url=callback_url,
                                                            redirect_url=redirect_url)
    pay_page_response = settings.phonepe_client.pay(pay_request)
    pay_page_url = pay_page_response.data.instrument_response.redirect_info.url

    # prodid = pi
    # usr = request.user.id
    # date = datetime.now()
    # # quantity= request.POST['qty']
    # amount = pay_request.amount / 100
    # phone_pay_order_id = pay_page_response.data.merchant_transaction_id
    #
    # orderobj = Order(productid=prodid, userid_id=usr, orderdate=date, order_price=amount, razor_pay_order_id=phone_pay_order_id, order_status=False, address=request.user.currentaddress,quantity=qt)
    # orderobj.save()

    current_user = User.objects.get(username=request.user)
    count_cart = Cart.objects.filter(user_id=current_user.id).count()
    return render(request, "buynow_checkout.html",{'cb': float(cb), 'tot': float(prod_price), 'item': count_cart, 'payment_url': pay_page_url, 'cart': countcart, 'pooja': count_puja})


def Checkout(request):
    
    current_user = User.objects.get(username=request.user)
    countcart = Cart.objects.filter(user_id=current_user.id).count()
    count_puja = PujaSlotBooking.objects.filter(user_id=current_user.id).count()
    user = User.objects.get(id=request.user.id)
    prod11 = PayByWalletAmount.objects.get(userid=user)
    cb = prod11.walletid
    # for i in prod11:
    #     print('i',i.amount)
    #     cb = cb + float(i.amount)
    # print(cb)
    print(user)
    prod = Cart.objects.filter(user_id=user.id).order_by('id').reverse()
    print(prod)
    pi = []
    for i in prod:
        i= pi.append(i.product.prodname)
    print("My Product", pi) 
    c = 0
    for i in prod:
        c = c + float(i.product.offerprice)
    print(c)   
    
    
    qt = 0
    for i in prod:
        qt+=int(i.quantity)
           
    ls = []
    tot = 0
    for pro in prod:
        print('Thisssssss',type(pro.product.offerprice))
        amt = float(pro.product.offerprice)
        qty = int(pro.quantity)
        print("wedfefefefef feff",type(amt))
        # pro = ls.append(amt)
        # qty = ls.append(qty)
        total = amt*qty
        ls.append(total)
        tot = sum(ls)

        print(tot)
        
        mylist = zip(prod, ls)
    # if float(cb)>=float(tot):

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
    # # address = addr.address
    #
    # orderobj = Order(productid=prodid,userid_id=usr,orderdate=date,order_price=amount,razor_pay_order_id=razor_pay_order_id,order_status=False,address=request.user.currentaddress,quantity=qt)
    # orderobj.save()
    # messages.success(request, "Order created....")
    
    # After Checkout cart will 0
    # prod.delete()

    ##################################################################################################
    # PHONEPE CODE
    ##################################################################################################
    unique_transaction_id = str(uuid.uuid4())
    ui_redirect_url = settings.redirect_base_url + reverse("order_success") + f'?transaction_id={unique_transaction_id}&amount={int(tot)}'
    s2s_callback_url = settings.redirect_base_url + reverse("order_success") + f'?transaction_id={unique_transaction_id}&amount={int(tot)}'
    amount = int(tot) * 100
    id_assigned_to_user_by_merchant = user.id
    pay_request = PgPayRequest.pay_page_pay_request_builder(merchant_transaction_id=unique_transaction_id,
                                                            amount=amount,
                                                            merchant_user_id=id_assigned_to_user_by_merchant,
                                                            callback_url=s2s_callback_url,
                                                            redirect_url=ui_redirect_url)
    pay_page_response = settings.phonepe_client.pay(pay_request)
    pay_page_url = pay_page_response.data.instrument_response.redirect_info.url

    # prodid = pi
    # usr = request.user.id
    # date = datetime.now()
    # # quantity= request.POST['qty']
    # amount = pay_request.amount / 100
    # phone_pay_order_id = pay_page_response.data.merchant_transaction_id
    #
    # orderobj = Order(productid=prodid, userid_id=usr, orderdate=date, order_price=amount, razor_pay_order_id=phone_pay_order_id, order_status=False, address=request.user.currentaddress,quantity=qt)
    # orderobj.save()

    print(tot)  
    print(ls)
    
    current_user = User.objects.get(username=request.user)
    count_cart = Cart.objects.filter(user_id=current_user.id).count()
    return render(request, "checkout.html",
                  {'cb':float(cb),'tot':float(tot),'cartprod':prod, 'item':count_cart, 'totalamt':c,
                   'payment_url':pay_page_url, 'mylist':mylist,'cart':countcart,'pooja':count_puja})
    # return render(request, "checkout.html")
    # else:
    #     return render(request, "incufficient.html")




def QusAndAnswerView(request):
    try:
        current_user = User.objects.get(username=request.user)
        count_cart = Cart.objects.filter(user_id=current_user.id).count()
        count_puja = PujaSlotBooking.objects.filter(user_id=current_user.id).count()
        
        quscat = CategoryOfFAQ.objects.all()
        time = AnswerFAQTime.objects.all()
        current_user = User.objects.get(username=request.user)
        profiles = FamilyFriendsprofile.objects.filter(ask_by=current_user)
        
        
        if request.method == 'POST':
            catname = request.POST['category']
            timing = request.POST['answertime']
            qus = request.POST['qus']
            # username = request.user.id
            username = request.POST['ask_qus']
            # date = datetime.now()

            # user_obj = QusAndAnswer(category_id=catname, answertime_id=timing, qus=qus, userid_id=request.user.id,ask_date=date,friend=username)
            # user_obj.save()
            
            #(request, 'Pay here to get answer successfully.')
            return redirect(f'/service/ask-a-question/checkout/?category_id={catname}&answer_time={timing}&friend={username}&question={qus}')
        else:
            return render(request, "askquestion.html", {'cate':quscat, 'anstime':time, 'relation':profiles,'cart':count_cart,'pooja':count_puja})
    except User.DoesNotExist:
             return redirect(f'/login/?next=/service/ask-a-question/')
            
            
    
def QusAndAnswerViewPayment(request):
    user = User.objects.get(id=request.user.id)
    print(user)
    current_user = User.objects.get(username=request.user)
    count_cart = Cart.objects.filter(user_id=current_user.id).count()
    count_puja = PujaSlotBooking.objects.filter(user_id=current_user.id).count()
    prod11 = PayByWalletAmount.objects.get(userid=user)
    cb = prod11.walletid

    category_id = request.GET.get('category_id')
    answer_time = request.GET.get('answer_time')
    answer_price = AnswerFAQTime.objects.get(id=int(answer_time)).price
    friend = request.GET.get('friend')
    question = request.GET.get('question')

    quscat = CategoryOfFAQ.objects.all()
    time = AnswerFAQTime.objects.all()
    current_user = User.objects.get(username=request.user)
    profiles = FamilyFriendsprofile.objects.filter(ask_by=current_user)
    
    
    prod = QusAndAnswer.objects.filter(userid=user.id)
    print(prod[len(prod)-1].id)
    
    
    # pi = []
    # for i in prod:
    #     i= pi.append(i.id)
    # print("My Product", pi)
    c = 0
    for i in prod:
        c = int(i.answertime.price)

    print(type(c))
    
    # if float(cb)>=float(c):

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
    # qustion = prod[len(prod)-1].qus
    # prodid = prod[len(prod)-1].id
    # usr = request.user.id
    # date = datetime.now()
    # # quantity= request.POST['qty']
    # amount = payment['amount']/100
    # razor_pay_order_id = payment['id']
    #
    # orderobj = QusAndAnswerPayment(askqusid_id=prodid,userid_id=usr,orderdate=date,order_price=amount,razor_pay_order_id=razor_pay_order_id,order_status=True)
    # orderobj.save()

    ##################################################################################################
    # PHONEPE CODE
    ##################################################################################################
    unique_transaction_id = str(uuid.uuid4())

    ui_redirect_url = settings.redirect_base_url + reverse("askastro_success") + f'?transaction_id={unique_transaction_id}&amount={c}&category_id={category_id}&answer_time={answer_time}&friend={friend}&question={question}'
    s2s_callback_url = settings.redirect_base_url + reverse("askastro_success") + f'?transaction_id={unique_transaction_id}&amount={c}&category_id={category_id}&answer_time={answer_time}&friend={friend}&question={question}'
    amount = int(answer_price) * 100
    id_assigned_to_user_by_merchant = user.id
    pay_request = PgPayRequest.pay_page_pay_request_builder(merchant_transaction_id=unique_transaction_id,
                                                            amount=amount,
                                                            merchant_user_id=id_assigned_to_user_by_merchant,
                                                            callback_url=s2s_callback_url,
                                                            redirect_url=ui_redirect_url)
    pay_puja_response = settings.phonepe_client.pay(pay_request)
    pay_page_url = pay_puja_response.data.instrument_response.redirect_info.url

    # qustion = prod[len(prod) - 1].qus
    # prodid = prod[len(prod)-1].id
    # usr = request.user.id
    # date = datetime.now()
    # # quantity= request.POST['qty']
    amount = pay_request.amount / 100
    # phone_pay_order_id = pay_puja_response.data.merchant_transaction_id
    #
    # orderobj = QusAndAnswerPayment(askqusid_id=prodid,userid_id=usr,orderdate=date,order_price=amount,razor_pay_order_id=phone_pay_order_id,order_status=True)
    # orderobj.save()
    #
    # # updt = QusAndAnswer.objects.filter(id=id)
    # prod.update(is_paid=True)


    # return redirect('/service/ask-a-question/')
    
    return render(request, "checkoutforqa.html", {'cb':float(cb),'tot':float(c),'cate':quscat, 'anstime':time, 'relation':profiles,'cart':count_cart,'pooja':count_puja, 'payment_url':pay_page_url,'qustion':question,'amount':amount})
# else:
    #     return render(request, "incufficient.html")
 
def ShowProfileDetail(request):
    try:
        current_user = User.objects.get(username=request.user)
        count_cart = Cart.objects.filter(user_id=current_user.id).count()
        count_puja = PujaSlotBooking.objects.filter(user_id=current_user.id).count()
        current_user = User.objects.get(username=request.user)
        return render(request, "profile.html", {"user":current_user,'cart':count_cart,'pooja':count_puja})
    except User.DoesNotExist:
             return redirect(f'/login/?next=/profile/')
    
    
def ShowFAQReply(request):   
    try:
        current_user = User.objects.get(username=request.user)
        count_cart = Cart.objects.filter(user_id=current_user.id).count()
        count_puja = PujaSlotBooking.objects.filter(user_id=current_user.id).count()
        user = User.objects.get(id=request.user.id)
        faq = QusAndAnswer.objects.filter(userid=user).order_by('-id')
        
        paginator = Paginator(faq, 6)
        page_number = request.GET.get('page')
        all_lead = paginator.get_page(page_number)
        totalpage = all_lead.paginator.num_pages
        # for i in all_lead:
        #     print(i)
        context = {
            'all_lead':all_lead,
            'lastpage':totalpage,
            'totalPagelist':[n+1 for n in range(totalpage)],
            'faq':faq,
            'cart':count_cart,
            'pooja':count_puja
        }
        return render(request, "faqanswer.html", context)
    except User.DoesNotExist:
             return redirect(f'/login/?next=/service/questions/reply/')

def ShowOrderlist(request):   
    try:
        
        current_user = User.objects.get(username=request.user)
        count_cart = Cart.objects.filter(user_id=current_user.id).count()
        count_puja = PujaSlotBooking.objects.filter(user_id=current_user.id).count()
        user = User.objects.get(id=request.user.id)
        prodord = Order.objects.filter(userid=user).order_by('-id')
        
        paginator = Paginator(prodord, 6)
        page_number = request.GET.get('page')
        all_lead = paginator.get_page(page_number)
        totalpage = all_lead.paginator.num_pages
        # for i in all_lead:
        #     print(i)
        context = {
            'all_lead':all_lead,
            'lastpage':totalpage,
            'totalPagelist':[n+1 for n in range(totalpage)],
            'cart':count_cart,
            'pooja':count_puja
        }
        return render(request, "userproductorder.html", context)
    except User.DoesNotExist:
             return redirect(f'/login/?next=/product/order/history/')


def ShowPojaSlot(request):
    try:
        current_user = User.objects.get(username=request.user)
        count_cart = Cart.objects.filter(user_id=current_user.id).count()
        count_puja = PujaSlotBooking.objects.filter(user_id=current_user.id).count()
        user = User.objects.get(id=request.user.id)
        pujaord = PoojaOrder.objects.filter(userid=user).order_by('-id')
        
        paginator = Paginator(pujaord, 6)
        page_number = request.GET.get('page')
        all_lead = paginator.get_page(page_number)
        totalpage = all_lead.paginator.num_pages
        # for i in all_lead:
        #     print(i)
        context = {
            'all_lead':all_lead,
            'lastpage':totalpage,
            'totalPagelist':[n+1 for n in range(totalpage)],
            'cart':count_cart,
            'pooja':count_puja,
            'pujaord':pujaord
        }
        return render(request, "userpujaorder.html", context)
    except User.DoesNotExist:
             return redirect(f'/login/?next=/puja/order/history/')
    

def ShowFaqPayment(request):
    try:
        current_user = User.objects.get(username=request.user)
        count_cart = Cart.objects.filter(user_id=current_user.id).count()
        count_puja = PujaSlotBooking.objects.filter(user_id=current_user.id).count()
        user = User.objects.get(id=request.user.id)
        faqpay = QusAndAnswerPayment.objects.filter(userid=user).order_by('-id')
        
        paginator = Paginator(faqpay, 6)
        page_number = request.GET.get('page')
        all_lead = paginator.get_page(page_number)
        totalpage = all_lead.paginator.num_pages
        # for i in all_lead:
        #     print(i)
        context = {
            'all_lead':all_lead,
            'lastpage':totalpage,
            'totalPagelist':[n+1 for n in range(totalpage)],
            'cart':count_cart,
            'pooja':count_puja,
            'faqpay':faqpay
        }
        return render(request, "useruespayment.html", context)
    except User.DoesNotExist:
             return redirect(f'/login/?next=/service/ask-a-question/payment/history/')
    
def UserRegister(request):
    code = CountryCode.objects.all()
    if request.method == 'POST':
        name = request.POST['fname']
        lname = request.POST['lname']
        email = request.POST['email']
        username = request.POST['usernm']
        password = request.POST['password']
        profilimg = request.FILES['profile']
        gend = request.POST['gender']
        phone = request.POST['contact']
        code = request.POST['code']
        lang = request.POST['language']
        birthdate = request.POST['dob']
        marid = request.POST['marital']
        birthtime = request.POST['timebirth']
        place = request.POST['place']
        addr = request.POST['address']
        date = datetime.now()
        try:
            if User.objects.filter(username = username).first():
                #(request, 'Username is already exist.')
                return redirect('/register/')

            if User.objects.filter(email = email).first():
                #(request, 'Email is already exist.')
                return redirect('/register/')
            
            user_obj = User(first_name=name, 
                            last_name=lname, 
                            email=email, 
                            username=username, 
                            password=make_password(password), 
                            profilepicture=profilimg, 
                            is_user=True, 
                            date_joined=date,
                            contactno=phone,
                            countrycode=code,
                            gender=gend,
                            language=lang,
                            dateofbirth=birthdate,
                            marital_status=marid,
                            timeofbirth=birthtime,
                            placeofbirth=place,
                            currentaddress=addr
                            )
            user_obj.save()
            messages.success(request, 'Username is register successfully.')
            return redirect('/register/')
            

        except Exception as e:
            print(e)
            return redirect('/register/')
    else:
        return render(request, "user_register.html",{'code':code})


def QuickRegister(request):
    if request.method == 'POST':
        name = request.POST['fname']
        lname = request.POST['lname']
        email = request.POST['email']
        password = request.POST['password']
        try:
            if User.objects.filter(email=email).first():
                # (request, 'Email is already exist.')
                return redirect('/sign-up/')

            user_obj = User(first_name=name,
                            last_name=lname,
                            email=email,
                            username=email,
                            password=make_password(password),
                            )
            user_obj.save()
            messages.success(request, 'Email is register successfully.')
            return redirect('/sign-up/')


        except Exception as e:
            print(e)
            return redirect('/sign-up/')
    else:
        return render(request, "sign-up.html")


def EditProfileView(request, id):
    current_user = User.objects.get(username=request.user)
    count_cart = Cart.objects.filter(user_id=current_user.id).count()
    count_puja = PujaSlotBooking.objects.filter(user_id=current_user.id).count()
    
    uplead = User.objects.filter(id=id)
    uplead1 = User.objects.get(id=id)
    if request.method == 'POST':
        fname = request.POST['fname']
        lname = request.POST['lname']
        email = request.POST['email']
        username = request.POST['usernm']
        contact = request.POST['phoneno']
        # code = request.POST['code']
        gend = request.POST['gender']
        lang = request.POST['language']
        birthdate = request.POST['dob']
        marid = request.POST['marital']
        birthtime = request.POST['timebirth']
        place = request.POST['place']
        addr = request.POST['address']
        
        if len(request.FILES) !=0:
            if len(uplead1.profilepicture) > 0:
                print('yessssssssssssssss1')
                os.remove(uplead1.profilepicture.path)
                # print(uplead1.profilepicture.path)
            uplead1.profilepicture = request.FILES['profilep']
            uplead1.save()
        
        uplead = User.objects.filter(id=id)
        
        uplead.update(first_name=fname,
                        last_name=lname,
                        email=email,
                        username=username,
                        contactno=contact,
                        # countrycode=code,
                        gender=gend,
                        language=lang,
                        dateofbirth=birthdate,
                        marital_status=marid,
                        timeofbirth=birthtime,
                        placeofbirth=place,
                        currentaddress=addr
                        )
        #(request, f"{fname}, profile updated successfully")
        # return redirect('/superadmin/edit_leadinfo//')
        return redirect(request.META.get('HTTP_REFERER', 'redirect_if_referer_not_found'))  
    else:
        getUser = User.objects.get(id=id)    
        return render(request, "edituser.html", {'user':getUser,'cart':count_cart,'pooja':count_puja})


def FamilyFriendCreate(request):
    relation = Relationship.objects.all()
    if request.method == 'POST':
        name = request.POST['fname']
        lname = request.POST['lname']
        gend = request.POST['gender']
        rel = request.POST['relation']
        birthdate = request.POST['dob']
        birthtime = request.POST['timebirth']
        place = request.POST['place']
        user = request.user.id
        
            
        user_obj = FamilyFriendsprofile(first_name=name, 
                        lastname=lname, 
                        gender=gend,
                        relationship_id=rel,
                        dateofbirth=birthdate,
                        timeofbirth=birthtime,
                        placeofbirth=place,
                        ask_by_id=user
                        )
        user_obj.save()
        #(request, 'Profile is create successfully.')
        return redirect('/view-family-friend/')
         
    else:
        return render(request, "friendsprofile.html", {'relation':relation})
        
        
    

def AddFriendView(request):
    current_user = User.objects.get(username=request.user)
    count_cart = Cart.objects.filter(user_id=current_user.id).count()
    count_puja = PujaSlotBooking.objects.filter(user_id=current_user.id).count()
    
    user = User.objects.get(id=request.user.id)
    getcreate = FamilyFriendsprofile.objects.filter(ask_by=user)#.order_by('id')
    return render(request, "getfamilyfriend.html", {'getdata':getcreate,'cart':count_cart,'pooja':count_puja})
    
    
def EditFriendProfileView(request, id):
    relation = Relationship.objects.all()
    if request.method == 'POST':
        name = request.POST['fname']
        lname = request.POST['lname']
        gend = request.POST['gender']
        rel = request.POST['relation']
        birthdate = request.POST['dob']
        birthtime = request.POST['timebirth']
        place = request.POST['place']
        user = request.user.id
        
        
        
        
        uplead = FamilyFriendsprofile.objects.filter(id=id)
        
        uplead.update(first_name=name, 
                        lastname=lname, 
                        gender=gend,
                        relationship_id=rel,
                        dateofbirth=birthdate,
                        timeofbirth=birthtime,
                        placeofbirth=place,
                        ask_by_id=user
                        )
        messages.success(request, f"{name}, profile updated successfully")
        return redirect('/view-family-friend/')
        # return redirect(request.META.get('HTTP_REFERER', 'redirect_if_referer_not_found'))  
    else:
        getUser = FamilyFriendsprofile.objects.get(id=id)    
        return render(request, "editfriendsprofile.html", {'user':getUser, 'relation':relation})



def DeleteFriendProfile(request, id):
    data = FamilyFriendsprofile.objects.get(id=id)
    data.delete()
    # messages.success(request, f"{data.product.prodname}, has been deleted succsessfull")
    return redirect('/view-family-friend/')

    
    

def GetOrderView(request):
    user = User.objects.get(id=request.user.id)
    getcreate = Order.objects.filter(userid=user)#.order_by('id')
    print(getcreate)
    return render(request, "productorderlist.html", {'getorderlist':getcreate})




def DailyBlosView(request):
    bloglist = DailyBlogs.objects.all()
    return render(request, "blog_single.html", {'blog':bloglist})

def SendCustomerSupport(request):
    try:
        current_user = User.objects.get(username=request.user)
        countcart = Cart.objects.filter(user_id=current_user.id).count()
        count_puja = PujaSlotBooking.objects.filter(user_id=current_user.id).count()
        if request.method == "POST":
            user = request.user.id
            msg = request.POST['message']
    
            user_obj = CustomerSupport(userid_id=user,message=msg)
            user_obj.save()
            #(request, 'Submitted successfully.')
            return redirect('/customer-support/')
        return render(request, "customersupport.html",{'cart':countcart,'pooja':count_puja})
    except:
             return redirect(f'/login/?next=/customer-support/')
def HoroscopeView(request):
    # Parse the input string into a datetime object
    input_string = datetime.now()
    input_datetime = input_string.strftime('%Y-%m-%dT%H:%M:%SZ')
    # Format the datetime object into the desired format
    # output_format = '%Y-%m-%dT%H:%M:%SZ'
    # formatted_datetime = input_datetime.strftime(output_format)
    print('formatted_datetime',input_datetime)
    payload = {'grant_type': 'client_credentials',
             'client_id': settings.prokerala_client_id,
             'client_secret': settings.prokerala_client_secret}
    r = requests.post('https://api.prokerala.com/token',data=payload)
    rq = r.json()
    #print(rq['access_token'])
    authh = rq['token_type']+' '+rq['access_token']
    payload = {'datetime': input_datetime, 'sign': 'leo'}
    headers = {'Authorization': authh}
    r1 = requests.get('https://api.prokerala.com/v2/horoscope/daily', params=payload, headers=headers)
    print(r1.json())
    rq1=r1.json()
    print(rq1['data']['daily_prediction']['prediction'])
    return render(request,'customersupport.html')


def FilterHoroscopeByCategory(request,id):
    try:
        # catname = HoroscopeCategory.objects.all()
        cateid  = HoroscopeCategory.objects.get(id=id)
        print("category ", str(cateid))
        catfilter = Horoscope.objects.filter(horscopname=cateid)
        # print("My category",catfilter[0].catname)
        input_string = datetime.now()
        input_datetime = input_string.strftime('%Y-%m-%dT%H:%M:%SZ')
        # Format the datetime object into the desired format
        # output_format = '%Y-%m-%dT%H:%M:%SZ'
        # formatted_datetime = input_datetime.strftime(output_format)
        print('formatted_datetime',input_datetime)
        payload={'grant_type':'client_credentials',
                #  'client_id':'65f7cd47-2762-4de2-a1af-a6916f3309a3',
                #  'client_secret':'5Ntne0tHhFsORHX0sQfu0uOjnauVhxffbxsYnzKP'}
                  'client_id':'bee8384c-f250-4bf8-9158-32d8bf198cf8',
                 'client_secret':'ZlbxATcO0wP6S4Mypfv98USJaCsyJlqDAns7FPsL'}
        r = requests.post('https://api.prokerala.com/token',data=payload)
        rq=r.json()
        print(rq['access_token'])
        authh =rq['token_type']+' '+rq['access_token']
        payload = {'datetime': input_datetime, 'sign': str(cateid).lower()}
        headers = {'Authorization': authh}
        r1 = requests.get('https://api.prokerala.com/v2/horoscope/daily', params=payload, headers=headers)
        print(r1.json())
        rq1=r1.json()
        # print(rq1['data']['daily_prediction']['prediction'])
        rqqcon=rq1['data']['daily_prediction']['prediction']
        return render(request, "horoscope_single.html", {'catid':cateid, 'catfilter':catfilter, 'content':rqqcon})
        # return render(request, "horoscope_single.html", {'catid':cateid, 'catfilter':catfilter})
    except KeyError:
        return redirect('/')
    
    
    
def DeleteCart(request, id):
    data = Cart.objects.get(id=id)
    data.delete()
    #(request, f"{data.product.prodname}, has been deleted succsessfull")
    return redirect('/view-cart/')


def DeletePoja(request, id):
    data = PujaSlotBooking.objects.get(id=id)
    data.delete()
    #(request, f"{data.pooja.name}, has been deleted succsessfull")
    return redirect('/puja-slot/')

def AddWalletAmount(request):
    current_user = User.objects.get(username=request.user)
    count_cart = Cart.objects.filter(user_id=current_user.id).count()
    count_puja = PujaSlotBooking.objects.filter(user_id=current_user.id).count()
    user = User.objects.get(id=request.user.id)
    qapay = QusAndAnswerPayment.objects.filter(userid=request.user.id,razor_pay_order_id='Wallet')
    prodpay = Order.objects.filter(userid=request.user.id,razor_pay_order_id='Wallet')
    pujapay = PoojaOrder.objects.filter(userid=request.user.id,razor_pay_order_id='Wallet')
    print('1111111',qapay)
    print('2222222',prodpay)
    print('3333333',pujapay)
    p=0
    for m in qapay:
        p=p+float(m.order_price)
    print('qqqqqqq',p)
    
    q=0
    for n in prodpay:
        q=q+float(n.order_price)
    print('qqqqqqq',q)
    
    r=0
    for o in pujapay:
        r=r+float(o.order_price)
    print('qqqqqqq',r)
    # for m,n,o in zip(qapay,prodpay,pujapay):
    #     #  p=p+float(m.order_price)
    #      q=q+float(n.order_price)
    #      r=r+float(o.order_price)
    print(p,',',q,',',r)
    z=p+q+r
    print('yyyyyyyyyy',z)
    prod = WalletAmt.objects.filter(userid=user)
    c = 0
    for i in prod:
        c = c + float(i.amount)
    print('xxxxx',c)
        
    uss=PayByWalletAmount.objects.filter(userid_id=request.user.id).exists()
    # print(uss.walletid)
    # var2=PayByWalletAmount.objects.get(userid_id=user)
    

    if uss:
        var2=PayByWalletAmount.objects.get(userid_id=user)
        chg=float(var2.walletid)
    else:
        chg=0
    
    print('sssssssssss',chg)
    print("dsdsdsd dsdsddw wewewe",prod)
    if request.method == "POST":
        # user = request.user.id
        amount = request.POST['amount']
        # var = WalletAdd(userwallet_id=user, walletamount=amount)
        # var.save()
        # uss=PayByWalletAmount.objects.filter(userid_id=request.user.id).exists()
        # print('hcawdskj',uss)
        # am = (float(c)-float(z))+float(amount)
        # print('jsdnfvjk',amount)
        # print('pppppppppppp',am)
        # if uss:
        #     var2=PayByWalletAmount.objects.filter(userid_id=user)
        #     var2.update(walletid=am)
        # else:
        #     var1 = PayByWalletAmount(userid_id=user, walletid=am)
        #     var1.save()
        #
        # messages.success(request, "Add wallet amount successfull..")
        return redirect(f'/confirm-payment/?amount={amount}')
    return render(request, "walletamount.html", {'amount':prod, 'amt':chg,'cart':count_cart,'pooja':count_puja})


def PaymentByRazorpay(request):
    current_user = User.objects.get(username=request.user)
    count_cart = Cart.objects.filter(user_id=current_user.id).count()
    count_puja = PujaSlotBooking.objects.filter(user_id=current_user.id).count()
    user = User.objects.get(id=request.user.id)
    print(user)
    prod = WalletAdd.objects.filter(userwallet=user)
    print(prod[0].id)
    
    
    # pi = []
    # for i in prod:
    #     i= pi.append(i.id)
    # print("My Product", pi)
    # c = 0
    # for i in prod:
    #     c = int(i.walletamount)
    #     print("MJKkksdskdfsdkfsdkfsn fksdjfidskjfd", c)
    # print(type(c))
    c = request.GET.get('amount')

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
    unique_transaction_id = str(uuid.uuid4())
    ui_redirect_url = settings.redirect_base_url + reverse("wallet_add_success") + f'?transaction_id={unique_transaction_id}&prodid={prod[0].id}'
    s2s_callback_url = settings.redirect_base_url + reverse("wallet_add_success") + f'?transaction_id={unique_transaction_id}&prodid={prod[0].id}'
    amount = int(c) * 100
    id_assigned_to_user_by_merchant = user.id
    pay_page_request = PgPayRequest.pay_page_pay_request_builder(merchant_transaction_id=unique_transaction_id,
                                                                 amount=amount,
                                                                 merchant_user_id=id_assigned_to_user_by_merchant,
                                                                 callback_url=s2s_callback_url,
                                                                 redirect_url=ui_redirect_url)
    pay_page_response = settings.phonepe_client.pay(pay_page_request)
    print("pay_page_response ::: ", pay_page_request)
    pay_page_url = pay_page_response.data.instrument_response.redirect_info.url

    # prodid = prod[0].id
    # usr = request.user.id
    # date = datetime.now()
    # # quantity= request.POST['qty']
    amount = pay_page_request.amount / 100
    # phone_pay_order_id = pay_page_response.data.merchant_transaction_id
    #
    # orderobj = WalletAmt(walt_id=prodid, userid_id=usr, amount=amount, orderdate=date,
    #                      razor_pay_order_id=phone_pay_order_id, order_status=True)
    # orderobj.save()

    # messages.success(request, 'Pay successfully.')
    # return redirect('/service/ask-a-question/'))
    return render(request, "walletcash.html", {'payment_url':pay_page_url,'cart':count_cart,'pooja':count_puja,'amount':amount})


# def ShowCurrentAmount(request):
#     user = User.objects.get(id=request.user.id)
#     print(user)
#     prod = WalletAmt.objects.filter(userid=user)
    
#     print(prod)
#     return render(request, "walletamount.html")
    
def PayWithWallet(request):
    direct_checkout = request.GET.get('direct_checkout', None)
    current_user = User.objects.get(username=request.user)
    count_cart = Cart.objects.filter(user_id=current_user.id).count()
    count_puja = PujaSlotBooking.objects.filter(user_id=current_user.id).count()
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
    if bool(direct_checkout):
        print("IN")
        context = request.session['context']
        prod_id = context['id'] or None
        prod_price = float(context['price']) or None
        prod = Products.objects.filter(id=int(prod_id))
        pi = []
        for i in prod:
            i = pi.append(i.prodname)
        c = 0
        for i in prod:
            c = c + float(i.offerprice)

        ls = []
        tot = 0
        for pro in prod:
            amt = float(pro.offerprice)
            # qty = int(pro.quantity)
            total = prod_price
            ls.append(total)
            tot = sum(ls)
            mylist = zip(prod, ls)
    else:
        print("ELSE")
        prod = Cart.objects.filter(user_id=user.id).order_by('id').reverse()
        print(prod)
        pi = []
        for i in prod:
            i= pi.append(i.product.prodname)
        print("My Product", pi)
        c = 0
        for i in prod:
            c = c + float(i.product.offerprice)


        ls = []
        tot = 0
        for pro in prod:
            print('Thisssssss',type(pro.product.offerprice))
            amt = float(pro.product.offerprice)
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
    upl = PayByWalletAmount.objects.get(userid=request.user.id)
    ll=upl.walletid
    amtminus=float(upl.walletid)-float(tot)
    uplead = PayByWalletAmount.objects.filter(userid=usr)
        
    uplead.update(walletid=amtminus)
    # py12=PayByWalletAmount.objects.get(id=request.user.id)
    # print('edhfcewkfjehn',py12.walletid)
    
    return render(request, "paywithwallet.html", {'ggg':cb,'cartprod':prod, 'll':ll, 'totalamt':tot, 'amtt':amtminus,'cart':count_cart,'pooja':count_puja})
    
    # return render(request, "checkout.html")
    
def CheckoutforPuja(request):
    
    user = User.objects.get(id=request.user.id)
    print(user)
    prod11 = PayByWalletAmount.objects.get(userid=user)
    cb = prod11.walletid
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
    
    pd=[]
    for i in prod:
        pd.append(i.dateofpuja)
    print("My Puja Date >>>>>>>>>>>>>>>>>>>>>>", pd) 
    
    c = 0
    for i in prod:
        c = c + float(i.pooja.offerprice)
 
    
    ls = []
    tot = 0
    for pro in prod:
        print('Thisssssss',type(pro.pooja.offerprice))
        amt = float(pro.pooja.offerprice)
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
    # pujadate = pd
    # prodid = pi
    # usr = request.user.id
    # date = datetime.now()
    # # quantity= request.POST['qty']
    # amount = payment['amount']/100
    # razor_pay_order_id = payment['id']
    #
    #
    # orderobj = PoojaOrder(pujaid=prodid,userid_id=usr,orderdate=date,order_price=amount,bookeddate=pujadate,razor_pay_order_id=razor_pay_order_id,order_status=False,address=request.user.currentaddress)
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
    unique_transaction_id = str(uuid.uuid4())
    ui_redirect_url = settings.redirect_base_url + reverse("puja_success") + f'?transaction_id={unique_transaction_id}&amount={int(tot)}'
    s2s_callback_url = settings.redirect_base_url + reverse("puja_success") + f'?transaction_id={unique_transaction_id}&amount={int(tot)}'
    amount = int(tot) * 100
    id_assigned_to_user_by_merchant = user.id
    pay_request = PgPayRequest.pay_page_pay_request_builder(merchant_transaction_id=unique_transaction_id,
                                                            amount=amount,
                                                            merchant_user_id=id_assigned_to_user_by_merchant,
                                                            callback_url=s2s_callback_url,
                                                            redirect_url=ui_redirect_url)
    pay_puja_response = settings.phonepe_client.pay(pay_request)
    pay_page_url = pay_puja_response.data.instrument_response.redirect_info.url

    pujadate = pd
    prodid = pi
    usr = request.user.id
    date = datetime.now()
    # quantity= request.POST['qty']
    amount = pay_request.amount / 100
    phone_pay_order_id = pay_puja_response.data.merchant_transaction_id

    orderobj = PoojaOrder(pujaid=prodid, userid_id=usr, orderdate=date, order_price=amount, bookeddate=pujadate,
                          razor_pay_order_id=phone_pay_order_id, order_status=False,
                          address=request.user.currentaddress)
    orderobj.save()

    current_user = User.objects.get(username=request.user)
    count_cart = Cart.objects.filter(user_id=current_user.id).count()
    return render(request, "checkoutforpuja.html", {'cb':float(cb),'tot':float(tot),'cartprod':prod, 'item':count_cart, 'totalamt':tot, 'payment_url':pay_page_url, 'mylist':mylist,'tot':tot, 'ggg':cb})
    # return render(request, "checkout.html")

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
        c = c + float(i.pooja.offerprice)
 
    
    ls = []
    tot = 0
    for pro in prod:
        print('Thisssssss',type(pro.pooja.offerprice))
        amt = float(pro.pooja.offerprice)
        
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
    upl = PayByWalletAmount.objects.get(userid=request.user.id)
    ll=upl.walletid
    amtminus=float(upl.walletid)-float(tot)
    uplead = PayByWalletAmount.objects.filter(userid=request.user.id)
        
    uplead.update(walletid=amtminus)
    # py12=PayByWalletAmount.objects.get(id=request.user.id)
    # print('edhfcewkfjehn',py12.walletid)
    
    return render(request, "paywithwalletforpuja.html", {'ggg':cb,'cartprod':prod, 'll':ll, 'totalamt':tot, 'amtt':amtminus})
    
    # return render(request, "checkout.html")

def CheckoutforQA(request):
    user = User.objects.get(id=request.user.id)
    print(user)
    prod11 = PayByWalletAmount.objects.get(userid=user)
    cb = prod11.walletid
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
        c = c + float(i.pooja.price)
    
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
    pay_pujaqa_response = settings.phonepe_client.pay(pay_request)
    pay_page_url = pay_pujaqa_response.data.instrument_response.redirect_info.url
        
    
    current_user = User.objects.get(username=request.user)
    count_cart = Cart.objects.filter(user_id=current_user.id).count()
    return render(request, "checkoutforqa.html", {'cb':float(cb),'tot':float(tot),'cartprod':prod, 'item':count_cart, 'totalamt':tot, 'payment_url':pay_page_url, 'mylist':mylist,'tot':tot, 'ggg':cb})
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
    #print("=================",request.user.currentaddress)
    user = User.objects.get(id=request.user.id)
    print(user)
    # addr = OrderPlaceAddress.objects.filter(userid=user)
    # print("dsfsfsfsd",addr)
    prod = QusAndAnswer.objects.filter(userid=request.user.id).order_by('id').reverse()
    print('This is test **** this is data ****',prod)
    
    a=prod[0].qus
    b=request.GET.get('amount')
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
    upl = PayByWalletAmount.objects.get(userid=request.user.id)
    ll=upl.walletid
    amtminus=float(upl.walletid)-float(b)
    uplead = PayByWalletAmount.objects.filter(userid=request.user.id)
        
    uplead.update(walletid=amtminus)
    # py12=PayByWalletAmount.objects.get(id=request.user.id)
    # print('edhfcewkfjehn',py12.walletid)
    
    return render(request, "paywithwalletforqa.html", {'ggg':cb,'cartprod':prod, 'll':ll, 'totalamt':b, 'amtt':amtminus})
    
    # return render(request, "checkout.html")
    
    
    
    
def SendMailToPassword(request):
    if request.method == 'POST':
        email = request.POST["email"]
        
        try:
            print("Hiiiiiiiiii")
            user = User.objects.get(email=email)
            print(user)
            print("Hello")
            send_mail(
                    'Response Mail',
                    f'Hi {user.first_name}, {user.last_name} \nWeclcome to Our Ask2Astro Your password change link here http://astro.techpanda.art/changeuserpassword/{user.id}/{user.username}',
                    'techpanda.sr@gmail.com',
                    [email],
                    fail_silently=False,
                )
            messages.success(request, "Check your email")
            return redirect('/forgot-password/')
        except User.DoesNotExist:
            # Handle error case where the email is not found
            messages.success(request, "Email id not found.")
            return redirect('/forgot-password/')        
   
    return render(request, "changepassform.html")



def UserForgotPassword(request,id,username):
    print(">>>>",id,username)
    usr = username
    
    
    
    oldpwd=User.objects.get(username=username)
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
        return redirect('/login/')
    return render(request,'passwordmail.html',{'usernm':usr,})
    
    
    
    
    
def Termsofuse(request):
    return render(request,'termsofuse.html')
    
def TermsandCondition(request):
    return render(request,'termsandconditions.html')
    
def PrivacyPolicy(request):
    return render(request,'privacypolicy.html')
    
def RefundPolicy(request):
    return render(request,'refundpolicy.html')
    
def ShippingPolicy(request):
    return render(request,'shippingpolicy.html')
    
# def Contact(request):
#     return render(request,'contact.html')
    
def ContactUs(request):
    return render(request,'contact.html')