# Generated by Django 4.2.2 on 2023-06-10 05:48

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('adminapp', '0006_products_category'),
    ]

    operations = [
        migrations.CreateModel(
            name='HoroscopeCategory',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('catname', models.CharField(max_length=200, null=True)),
            ],
        ),
        migrations.RemoveField(
            model_name='horoscope',
            name='horscopname',
        ),
    ]
