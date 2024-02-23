from django.db import models
from django.contrib.auth.models import AbstractUser
import os
import datetime
from datetime import date

def filepath(request, filename):
    old_filename = filename
    timeNow = datetime.datetime.now().strftime('%Y%m%d%H:%M:%S')
    filename = "%s%s" % (timeNow, old_filename)
    return os.path.join('profilepic/', filename)

class User(AbstractUser):
    is_user = models.BooleanField(default=False)
    contactno = models.CharField(max_length=12, null=True)
    profilepicture = models.ImageField(upload_to=filepath, blank=True, null=True)
    gender = models.CharField(max_length=12, null=True)
    language = models.CharField(max_length=50, null=True)
    dateofbirth = models.CharField(max_length=20, null=True)
    marital_status = models.CharField(max_length=50, null=True)
    timeofbirth = models.CharField(max_length=20, null=True)
    placeofbirth = models.CharField(max_length=100, null=True)
    currentaddress = models.CharField(max_length=300, null=True)
    mobileno = models.CharField(max_length=300, null=True)
    countrycode = models.CharField(max_length=50, null=True)
    houseno = models.CharField(max_length=300, null=True)
    area = models.CharField(max_length=300, null=True)
    landmark = models.CharField(max_length=300, null=True)
    pincode = models.CharField(max_length=300, null=True)
    towncity = models.CharField(max_length=300, null=True)
    state = models.CharField(max_length=300, null=True)
    
class CountryCode(models.Model):
    code = models.CharField(max_length=200, null=True)
    def __str__(self):
        return self.code

class Relationship(models.Model):
    relation = models.CharField(max_length=200, null=True)


class FamilyFriendsprofile(models.Model):
    first_name = models.CharField(max_length=100, null=True)
    lastname = models.CharField(max_length=100, null=True)
    gender = models.CharField(max_length=30, null=True)
    relationship = models.ForeignKey(Relationship, on_delete=models.CASCADE)
    dateofbirth = models.CharField(max_length=20, null=True)
    timeofbirth = models.CharField(max_length=20, null=True)
    placeofbirth = models.CharField(max_length=100, null=True)
    ask_by = models.ForeignKey(User,on_delete=models.CASCADE)
