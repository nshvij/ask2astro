# Generated by Django 4.2.2 on 2023-06-20 10:57

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('adminapp', '0030_alter_pooja_dateofpuja_qusandanswerpayment'),
    ]

    operations = [
        migrations.AlterField(
            model_name='pooja',
            name='dateofpuja',
            field=models.CharField(default=datetime.datetime(2023, 6, 21, 10, 57, 30, 267405), max_length=12, null=True),
        ),
    ]
