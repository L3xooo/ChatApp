from django.contrib import admin

# Register your models here.

from .models import  ChatMessage, Friend_request, Room, Topic, Message, User

admin.site.register(Room)
admin.site.register(Topic)
admin.site.register(Message)
admin.site.register(User)
admin.site.register(Friend_request)
admin.site.register(ChatMessage)
