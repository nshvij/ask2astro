# Generated by Django 4.2.2 on 2023-06-23 07:38

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0006_user_area_user_houseno_user_landmark_user_mobileno_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='state',
            field=models.CharField(max_length=300, null=True),
        ),
    ]
