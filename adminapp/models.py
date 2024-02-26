from django.db import models
from accounts.models import User
import os
import datetime
from datetime import date
# Create your models here.
from datetime import datetime, timedelta

 
# Get today's date
presentday = datetime.now() # or presentday = datetime.today()
tomorrow = presentday + timedelta(1)

print("Today = ", presentday.strftime('%m-%d-%Y'))
print("Tomorrow = ", tomorrow.strftime('%m-%d-%Y'))


def filepath(request, filename):
    old_filename = filename
    timeNow = datetime.datetime.now().strftime('%Y%m%d%H:%M:%S')
    filename = "%s%s" % (timeNow, old_filename)
    return os.path.join('panditimg/', filename)

class CreatePandit(models.Model):
    name = models.CharField(max_length=100, null=True)
    experience = models.CharField(max_length=150, null=True)
    languages = models.CharField(max_length=150, null=True)
    expertise_in = models.CharField(max_length=150, null=True)
    about = models.CharField(max_length=300, null=True)
    contact = models.CharField(max_length=12, null=True)
    panditpicture = models.ImageField(upload_to=filepath, blank=True, null=True)
    
    
class CategoryOfProduct(models.Model):
    catprod = models.CharField(max_length=200, null=True)
    active_status = models.BooleanField(default=True)
    
    
    def __str__(self):
        return self.catprod


def filepath2(request, filename):
    old_filename = filename
    timeNow = datetime.now().strftime('%Y%m%d%H:%M:%S')
    filename = "%s%s" % (timeNow, old_filename)
    return os.path.join('productimg/', filename)
    

class SKU(models.Model):
    category = models.ForeignKey(CategoryOfProduct, on_delete=models.CASCADE)
    sku_name = models.CharField(max_length=200)

    def __str__(self):
        return self.sku_name


class Products(models.Model):
    prodname = models.CharField(max_length=200, null=True)
    prodpicture = models.ImageField(upload_to=filepath2, blank=True, null=True)
    discription = models.CharField(max_length=500, null=True)
    price = models.CharField(max_length=200, null=True)
    quantity = models.CharField(max_length=200, null=True)
    category = models.ForeignKey(CategoryOfProduct, on_delete=models.CASCADE)
    offers = models.CharField(max_length=200, default=0)
    offerprice = models.CharField(max_length=200, default=0)
    active_status = models.BooleanField(default=True)
    sku = models.ForeignKey(SKU, on_delete=models.CASCADE, null=True, blank=True)
    sku_type = models.CharField(max_length=200, null=True, blank=True)

    def __str__(self):
        return self.prodname
        
def filepath3(request, filename):
    old_filename = filename
    timeNow = datetime.now().strftime('%Y%m%d%H:%M:%S')
    filename = "%s%s" % (timeNow, old_filename)
    return os.path.join('productimg/', filename)


class CategoryOfPooja(models.Model):
    catname = models.CharField(max_length=200, null=True)
    prodpicture = models.ImageField(upload_to=filepath3, blank=True, null=True)
    active_status = models.BooleanField(default=True)
    
    def __str__(self):
        return self.catname
    
class PoojaSlot(models.Model):
    slottime = models.CharField(max_length=10, null=True)
    def __str__(self):
        return self.slottime


def filepath4(request, filename):
    old_filename = filename
    timeNow = datetime.now().strftime('%Y%m%d%H:%M:%S')
    filename = "%s%s" % (timeNow, old_filename)
    return os.path.join('productimg/', filename)
    
    
class Pooja(models.Model):
    name = models.CharField(max_length=200, null=True)
    pojapicture = models.ImageField(upload_to=filepath4, blank=True, null=True)
    discription = models.CharField(max_length=250, null=True)
    needofpuja = models.CharField(max_length=450, null=True)
    advantages = models.CharField(max_length=500, null=True)
    pujasamagri = models.CharField(max_length=400, null=True)
    category = models.ForeignKey(CategoryOfPooja, on_delete=models.CASCADE)
    pujaslot = models.ForeignKey(PoojaSlot, on_delete=models.CASCADE, null=True)
    dateofpuja = models.CharField(max_length=12, null=True,default=tomorrow)
    price = models.CharField(max_length=200, null=True)
    offers = models.CharField(max_length=200, default=0)
    offerprice = models.CharField(max_length=200, default=0)
    faq = models.TextField(null=True)
    active_status = models.BooleanField(default=True)
    
    def __str__(self):
        return self.name


class Faq(models.Model):
    product = models.ForeignKey(Products, on_delete=models.CASCADE, null=True, blank=True)
    pooja = models.ForeignKey(Pooja, on_delete=models.CASCADE, related_name="pooja_faq", null=True, blank=True)
    question = models.CharField(max_length=200)
    answer = models.TextField(null=True)
    
    
class Order(models.Model):
    productid = models.JSONField(default=list, null=True)
    userid = models.ForeignKey(User,on_delete=models.CASCADE)
    orderdate = models.DateTimeField(auto_now=True)
    order_status = models.BooleanField(default=False)
    quantity = models.CharField(max_length=12, null=True)
    order_price = models.CharField(max_length=200, null=True)
    razor_pay_order_id = models.CharField(max_length=100, null=True, blank=True)
    razor_pay_payment_id = models.CharField(max_length=100, null=True, blank=True)
    razor_pay_payment_signature = models.CharField(max_length=100, null=True, blank=True)
    address = models.CharField(max_length=350, null=True)
    


class PoojaOrder(models.Model):
    pujaid = models.JSONField(default=list, null=True)
    userid = models.ForeignKey(User,on_delete=models.CASCADE)
    orderdate = models.DateTimeField(auto_now=True)
    order_status = models.BooleanField(default=False)
    bookeddate = models.JSONField(default=list, null=True)
    order_price = models.CharField(max_length=200, null=True)
    razor_pay_order_id = models.CharField(max_length=100, null=True, blank=True)
    razor_pay_payment_id = models.CharField(max_length=100, null=True, blank=True)
    razor_pay_payment_signature = models.CharField(max_length=100, null=True, blank=True)
    address = models.CharField(max_length=350, null=True)
    

class CategoryOfFAQ(models.Model):
    catname = models.CharField(max_length=200, null=True)
    
class AnswerFAQTime(models.Model):
    time = models.CharField(max_length=200, null=True)
    price = models.CharField(max_length=200, null=True)
    icon = models.CharField(max_length=200, null=True)
    package = models.CharField(max_length=200, null=True)
    exp = models.CharField(max_length=200, null=True)
    
class QusAndAnswer(models.Model):
    category = models.ForeignKey(CategoryOfFAQ,on_delete=models.CASCADE)
    answertime = models.ForeignKey(AnswerFAQTime,on_delete=models.CASCADE)
    qus = models.CharField(max_length=200, null=True)
    is_paid = models.BooleanField(default=False)
    is_answered = models.BooleanField(default=False)
    userid = models.ForeignKey(User,on_delete=models.CASCADE)
    friend = models.CharField(max_length=200, null=True)
    ans = models.CharField(max_length=200, null=True)
    ask_date = models.DateTimeField(auto_now=True)
    
class QusAndAnswerPayment(models.Model):
    askqusid = models.ForeignKey(QusAndAnswer, on_delete=models.CASCADE)
    userid = models.ForeignKey(User,on_delete=models.CASCADE)
    orderdate = models.DateTimeField(auto_now=True)
    order_status = models.BooleanField(default=False)
    quantity = models.CharField(max_length=12, null=True)
    order_price = models.CharField(max_length=200, null=True)
    razor_pay_order_id = models.CharField(max_length=100, null=True, blank=True)
    razor_pay_payment_id = models.CharField(max_length=100, null=True, blank=True)
    razor_pay_payment_signature = models.CharField(max_length=100, null=True, blank=True)
    
def filepath5(request, filename):
    old_filename = filename
    timeNow = datetime.now().strftime('%Y%m%d%H:%M:%S')
    filename = "%s%s" % (timeNow, old_filename)
    return os.path.join('horoscop/', filename)
    
    
class HoroscopeCategory(models.Model):
    catname = models.CharField(max_length=200, null=True)
    horoscopeimg = models.ImageField(upload_to=filepath5, blank=True, null=True)
    def __str__(self):
        return self.catname
    
    
class Horoscope(models.Model):
    horscopname = models.ForeignKey(HoroscopeCategory, on_delete=models.CASCADE)
    date = models.DateTimeField(auto_now=True)
    discription = models.CharField(max_length=1000, null=True)
    userid = models.ForeignKey(User,on_delete=models.CASCADE)
    
    def __str__(self):
        return self.horscopname.catname

def filepath6(request, filename):
    old_filename = filename
    timeNow = datetime.now().strftime('%Y%m%d%H:%M:%S')
    filename = "%s%s" % (timeNow, old_filename)
    return os.path.join('blog/', filename)
    
class DailyBlogs(models.Model):
    blogtitle = models.CharField(max_length=200,null=True)
    blogimg = models.FileField(upload_to=filepath6, blank=True, null=True)
    discription = models.TextField()
    date = models.DateField(auto_now=True)   
    
    
class CustomerSupport(models.Model):
    userid = models.ForeignKey(User,on_delete=models.CASCADE)
    message = models.CharField(max_length=800,null=True)

    def __str__(self):
        return self.userid.username
        
        
class OrderPlaceAddress(models.Model):
    userid = models.ForeignKey(User,on_delete=models.CASCADE)
    address = models.CharField(max_length=800,null=True)
    
    
class WalletAdd(models.Model):
    userwallet=models.ForeignKey(User,on_delete=models.CASCADE)
    walletamount=models.IntegerField()
    wallettime=models.DateTimeField(auto_now_add=True)
    walletstatus=models.BooleanField(default=False)
    
    
class WalletAmt(models.Model):
    walt = models.ForeignKey(WalletAdd,on_delete=models.CASCADE)
    userid = models.ForeignKey(User,on_delete=models.CASCADE)
    orderdate = models.DateTimeField(auto_now=True)
    order_status = models.BooleanField(default=False)
    amount = models.CharField(max_length=200, null=True)
    razor_pay_order_id = models.CharField(max_length=100, null=True, blank=True)
    razor_pay_payment_id = models.CharField(max_length=100, null=True, blank=True)
    razor_pay_payment_signature = models.CharField(max_length=100, null=True, blank=True)
    
class PayByWalletAmount(models.Model):
    userid = models.ForeignKey(User,on_delete=models.CASCADE)
    walletid = models.CharField(max_length=100)
    