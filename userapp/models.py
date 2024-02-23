from django.db import models
from accounts.models import User
from adminapp.models import *
# Create your models here.

class Cart(models.Model):
    
	class Meta():
		unique_together = ('user', 'product')     #using unique together do not create duplicate cart
	quantity = models.CharField(max_length=12, null=True)
	user = models.ForeignKey(User, on_delete=models.CASCADE)
	product = models.ForeignKey(Products, on_delete=models.CASCADE)
	address = models.CharField(max_length=350, null=True)
    
    

class PujaSlotBooking(models.Model):
    
	class Meta():
		unique_together = ('user', 'pooja')     #using unique together do not create duplicate cart
  

	user = models.ForeignKey(User, on_delete=models.CASCADE)
	pooja = models.ForeignKey(Pooja, on_delete=models.CASCADE)
	pujaslot = models.ForeignKey(PoojaSlot, on_delete=models.CASCADE)
	dateofpuja = models.CharField(max_length=12, null=True)
    
