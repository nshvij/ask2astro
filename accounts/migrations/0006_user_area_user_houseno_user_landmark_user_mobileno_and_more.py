# Generated by Django 4.2.2 on 2023-06-23 07:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0005_alter_user_profilepicture'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='area',
            field=models.CharField(max_length=300, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='houseno',
            field=models.CharField(max_length=300, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='landmark',
            field=models.CharField(max_length=300, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='mobileno',
            field=models.CharField(max_length=300, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='pincode',
            field=models.CharField(max_length=300, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='towncity',
            field=models.CharField(max_length=300, null=True),
        ),
    ]
