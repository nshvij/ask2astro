# Generated by Django 4.2.2 on 2023-06-08 07:29

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='profilepicture',
            field=models.ImageField(blank=True, null=True, upload_to='profilepic'),
        ),
    ]
