# Generated by Django 4.0.5 on 2022-08-25 12:04

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0005_remove_chatmessage_chat_remove_chatmessage_user_and_more'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='chat',
            options={'ordering': ['last_used']},
        ),
        migrations.AlterModelOptions(
            name='chatmessage',
            options={'ordering': ['created']},
        ),
        migrations.RemoveField(
            model_name='chat',
            name='name',
        ),
        migrations.RemoveField(
            model_name='chat',
            name='participants',
        ),
        migrations.AddField(
            model_name='chat',
            name='last_used',
            field=models.DateTimeField(null=True),
        ),
        migrations.AddField(
            model_name='chat',
            name='user',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='user',
            name='chats',
            field=models.ManyToManyField(blank=True, related_name='chat', to='base.chat'),
        ),
    ]
