# Generated by Django 4.2.2 on 2023-06-13 07:53

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('userapp', '0002_pujaslotbooking'),
    ]

    operations = [
        migrations.AddField(
            model_name='cart',
            name='quantity',
            field=models.IntegerField(default='2'),
            preserve_default=False,
        ),
    ]
