from distutils.command import upload
from tkinter import CASCADE
from django.db import models
from django.contrib.auth.models import AbstractUser 

# Create your models here.
class User(AbstractUser):
    email = models.EmailField(null = True,unique=True)
    name = models.CharField(max_length=200, null = True)
    bio = models.TextField(null = True)
    avatar = models.ImageField(null = True,default = 'avatar.svg')
    requests = models.ManyToManyField("Friend_request",blank = True)
    friends = models.ManyToManyField("User",blank = True)
    chat_with = models.ManyToManyField("User",blank = True,related_name="Chat_with")

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.email

class Friend_request(models.Model):
    from_user = models.ForeignKey(User,related_name='from_user',on_delete = models.CASCADE)
    to_user = models.ForeignKey(User,related_name='to_user',on_delete = models.CASCADE)


class Topic(models.Model):
    name = models.CharField(max_length=200)
    def __str__(self):
        return self.name


class Room(models.Model):
    host            = models.ForeignKey(User, on_delete = models.SET_NULL, null = True)
    topic           = models.ForeignKey(Topic, on_delete = models.SET_NULL, null = True)
    name            = models.CharField(max_length=200)
    description     = models.TextField(null = True,blank = True)
    participants    = models.ManyToManyField(User,related_name = 'participants',blank = True)
    updated         = models.DateTimeField(auto_now = True)
    created         = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-updated','-created']

    def __str__(self):
        return self.name


class Message(models.Model):
    user    = models.ForeignKey(User, on_delete = models.CASCADE)
    room    = models.ForeignKey(Room, on_delete = models.CASCADE)
    body    = models.TextField()
    updated = models.DateTimeField(auto_now = True)
    created = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-updated','-created']

    def __str__(self):
        return self.body[0:50]

class ChatMessage(models.Model):
    author = models.ForeignKey(User, on_delete = models.CASCADE,related_name='author',null = True)
    reciever = models.ForeignKey(User, on_delete = models.CASCADE,related_name='reciever',null = True)
    body = models.TextField()
    created = models.DateTimeField(auto_now_add=True)
    seen = models.BooleanField(default=False)

    class Meta:
        ordering = ['created']

    def __str__(self):
        return self.body[0:50]