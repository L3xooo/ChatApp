# Generated by Django 4.0.5 on 2022-08-29 16:41

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0009_chatmessage_seen'),
    ]

    operations = [
        migrations.AlterField(
            model_name='chatmessage',
            name='seen',
            field=models.BooleanField(default=False),
        ),
    ]
