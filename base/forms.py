from urllib import request
from django import forms
from django.forms import ModelForm, ValidationError
from django.contrib.auth.forms import UserCreationForm
from .models import Room, User
from django.contrib.auth import authenticate

class MyUserCreationForm(UserCreationForm):
    class Meta:
        model = User
        fields = ['name','username','email','password']

class RoomForm(ModelForm):
    class Meta:
        model = Room
        fields = '__all__'
        exclude = ['host','participants']

class ForgetPasswordForm(forms.Form):
    email = forms.EmailField(required=True) 

    def clean(self):
        cleaned_data = super().clean()
        email = cleaned_data.get('email')
        try:
            email = User.objects.get(email = email)
        except:
            raise forms.ValidationError("Sorry, user with this email does not exist. Please try again.")

    def get_email(self,request):
        cleaned_data = super().clean()
        email = cleaned_data.get('email')
        return email

class NewPasswordForm(forms.Form):
    old_password_flag = True
    old_password = forms.CharField(widget=forms.PasswordInput, required=False)
    new_password = forms.CharField(widget=forms.PasswordInput, required=True)
    confirm_password = forms.CharField(widget=forms.PasswordInput, required=True)

    def clean(self):
        cleaned_data = super().clean()
        new_password = cleaned_data.get('new_password')
        confirm_password = cleaned_data.get('confirm_password')
        if new_password != confirm_password:
            raise forms.ValidationError("Passwords dont match.")
        if self.old_password_flag == False:
            raise forms.ValidationError("The old password that you entered is wrong.")

class LoginForm(forms.Form):
    email = forms.EmailField(required=True)
    password = forms.CharField(widget=forms.PasswordInput, required=True)

    def clean(self):
        cleaned_data = super().clean()
        email = cleaned_data.get('email')
        password = cleaned_data.get('password')
        print(password)
        user = authenticate(email = email, password = password)
        if user is None:
            raise forms.ValidationError("Sorry, that login was invalid. Please try again.")
        

    def login(self,request):
        cleaned_data = super().clean()
        email = cleaned_data.get('email')
        password = cleaned_data.get('password')
        user = authenticate(email = email , password=password)
        return user


class SettingsForm(UserCreationForm):
    class Meta:
        model = User
        fields = ['avatar','name','username','email','bio']


class ChangePasswordForm(forms.Form):
    old_password_flag = True
    old_password = forms.CharField(widget=forms.PasswordInput, required=True)
    new_password = forms.CharField(widget=forms.PasswordInput, required=True)
    confirm_password = forms.CharField(widget=forms.PasswordInput, required=True)
    
    def clean(self):
        cleaned_data = super().clean()
        new_password = cleaned_data.get('new_password')
        confirm_password = cleaned_data.get('confirm_password')
        if new_password != confirm_password:
            raise forms.ValidationError("Passwords dont match.")
        if self.old_password_flag == False:
            raise forms.ValidationError("The old password that you entered is wrong.")