# Generated by Django 4.2.2 on 2023-06-23 07:38

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('adminapp', '0043_alter_pooja_dateofpuja'),
    ]

    operations = [
        migrations.AlterField(
            model_name='pooja',
            name='dateofpuja',
            field=models.CharField(default=datetime.datetime(2023, 6, 24, 7, 38, 53, 451488), max_length=12, null=True),
        ),
    ]
