# Generated by Django 4.2.2 on 2023-06-14 10:39

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('adminapp', '0020_poojaslot'),
    ]

    operations = [
        migrations.AddField(
            model_name='pooja',
            name='pujaslot',
            field=models.ForeignKey(default='1', on_delete=django.db.models.deletion.CASCADE, to='adminapp.poojaslot'),
            preserve_default=False,
        ),
    ]
