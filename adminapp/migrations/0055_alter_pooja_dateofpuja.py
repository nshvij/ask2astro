# Generated by Django 4.2.2 on 2023-07-04 13:29

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('adminapp', '0054_alter_pooja_dateofpuja'),
    ]

    operations = [
        migrations.AlterField(
            model_name='pooja',
            name='dateofpuja',
            field=models.CharField(default=datetime.datetime(2023, 7, 5, 13, 29, 47, 188151), max_length=12, null=True),
        ),
    ]
