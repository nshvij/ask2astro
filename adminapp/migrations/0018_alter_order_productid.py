# Generated by Django 4.2.2 on 2023-06-14 08:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('adminapp', '0017_order_razor_pay_order_id_order_razor_pay_payment_id_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='order',
            name='productid',
            field=models.JSONField(default=list, null=True),
        ),
    ]
