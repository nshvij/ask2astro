# Generated by Django 4.2.2 on 2023-06-13 12:50

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('adminapp', '0014_answerfaqtime'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='qusandanswer',
            name='qusprice',
        ),
        migrations.AddField(
            model_name='qusandanswer',
            name='answertime',
            field=models.ForeignKey(default='2', on_delete=django.db.models.deletion.CASCADE, to='adminapp.answerfaqtime'),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='qusandanswer',
            name='is_answered',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='qusandanswer',
            name='is_paid',
            field=models.BooleanField(default=False),
        ),
    ]
