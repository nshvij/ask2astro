# Generated by Django 4.2.3 on 2023-08-07 16:14

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('adminapp', '0058_alter_pooja_dateofpuja'),
    ]

    operations = [
        migrations.AlterField(
            model_name='pooja',
            name='dateofpuja',
            field=models.CharField(default=datetime.datetime(2023, 8, 8, 21, 44, 49, 226491), max_length=12, null=True),
        ),
    ]
