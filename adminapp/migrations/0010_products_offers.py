# Generated by Django 4.2.2 on 2023-06-10 10:46

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('adminapp', '0009_horoscope_horscopname'),
    ]

    operations = [
        migrations.AddField(
            model_name='products',
            name='offers',
            field=models.CharField(default=0, max_length=200),
        ),
    ]
