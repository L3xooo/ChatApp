import datetime
import json
from django.shortcuts import render, redirect
from django.db.models import Q
from .models import ChatMessage, Room, Topic, Message, User, Friend_request
from .forms import ChangePasswordForm, ForgetPasswordForm, LoginForm, NewPasswordForm, RoomForm
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.core.files.storage import FileSystemStorage
from django.core.mail import EmailMessage
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.hashers import check_password
from django.template.loader import render_to_string
from .tokens import account_activation_token
from django.core.paginator import Paginator
from django.http import JsonResponse


def loginPage(request):
    if request.user.is_authenticated:
        return redirect('home')
    if request.method == 'POST': 
        form = LoginForm(request.POST or None)
        if form.is_valid():
            user = form.login(request)
            if user:
                login(request, user)
                return redirect("home")
    else:
        form = LoginForm()
    return render(request, 'base/login.html',{"form" : form})


def forget_passwordPage(request):
    if request.method == "GET":
        form = ForgetPasswordForm(request.GET or None)
        if form.is_valid():
            email = form.get_email(request)
            user = User.objects.get(email=email)
            # to get the domain of the current site
            current_site = get_current_site(request)
            mail_subject = 'Password reset'
            message = render_to_string('base/test.html', {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': account_activation_token.make_token(user),
            })
            to_email = form.cleaned_data.get('email')
            email = EmailMessage(
                mail_subject, message, to=[to_email]
            )
            email.send()
            return render(request, 'base/forget_password.html', context={'form': form, 'to_email': to_email})
        else:
            print(form.errors)
    else:
        form = ForgetPasswordForm()
    return render(request, 'base/forget_password.html', context={'form': form})


def passwordEmailView(request):
    return render(request, 'base/password_email.html')


# https://www.javatpoint.com/django-user-registration-with-email-confirmation
def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
        print(user)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        if request.method == "POST":
            form = NewPasswordForm(request.POST or None)
            if form.is_valid():
                password = request.POST.get('new_password')
                user.set_password(password)
                user.save()
                success = True
                return render(request, 'base/acc_active_email.html', context={'form': form, 'success': success})
        else:
            form = NewPasswordForm()
    return render(request, 'base/acc_active_email.html', context={'form': form})


def passwordChange(request, pk):
    user = User.objects.get(id=pk)
    if request.method == "POST":
        form = NewPasswordForm(request.POST or None)
        old_password = request.POST.get('old_password')
        if check_password(old_password, user.password) == False:
            form.old_password_flag = False
        if form.is_valid():
            password = request.POST.get('new_password')
            user.set_password(password)
            user.save()
            success = True
            login(request, user)
            # dorobit autolog po zmene hesla
            return render(request, 'base/acc_active_email.html', context={'form': form, 'success': success})
    else:
        form = ChangePasswordForm()
    return render(request, 'base/acc_active_email.html', context={'form': form})


def logoutUser(request):
    logout(request)
    return redirect('home')


def error_404_view(request, exception):
    return render(request, "base/error.html")


def registerPage(request):
    if request.method == "POST":
        name = request.POST.get('name')
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        if password == confirm_password:
            user = User.objects.create_user(
                username=username,
                password=password,
                name=name,
                email=email
            )
            return redirect('home')
        else:
            messages.error(request, 'hesla sa nezhoduju')
            return render(request, 'base/signup.html', context={'name': name, 'username': username, 'email': email})
    return render(request, "base/signup.html", context={})


def topics(request):
    if 'q' in request.GET:
        search = request.GET['q']
        topics = Topic.objects.filter(name__icontains=search)
    else:
        search = ""
        topics = Topic.objects.all()[:5]
    context = {'topics': topics, 'search': search}
    return render(request, 'base/topics.html', context)


def home(request):
    if request.GET.get('k') != None:
        q = request.GET.get('k')
        rooms = Room.objects.filter(
        Q(topic__name=q))
        room_messages = Message.objects.filter(Q(
        room__topic__name=q))[:2]
    else:
        if request.GET.get('q') != None:
            q = request.GET.get('k')
        else:
            q = ''
        rooms = Room.objects.filter(
        Q(topic__name__icontains=q) |
        Q(name__icontains=q) |
        Q(description__icontains=q)
        )
        room_messages = Message.objects.filter(Q(
        room__topic__name__icontains=q))[:2]
        
    topics = Topic.objects.all()
    room_count = rooms.count()
    paginator = Paginator(rooms, 3)
    page_number = request.GET.get('page')
    test = paginator.get_page(page_number)

    if request.user.is_authenticated:
        user = request.user
        friends = user.friends.all()
        to_user = user.requests.values_list("to_user", flat=True)
        from_user = user.requests.values_list("from_user", flat=True)
        users = User.objects.all()
        requests = user.requests.all()
        fr_req = user.requests.filter(to_user=user)
        send = Friend_request.objects.filter(from_user=user)
        context = {'rooms': rooms, 'topics': topics,
                   'room_count': room_count, 'room_messages': room_messages, 'users': users, 'requests': requests,
                   'friends': friends, 'send': send, 'test': test, 'fr_req': fr_req, "to_user": to_user, 'from_user': from_user}
    else:
        users = User.objects.all()
        context = {'rooms': rooms, 'topics': topics,
                   'room_count': room_count, 'room_messages': room_messages, 'users': users, 'test': test}
    return render(request, 'base/home.html', context)


def room(request, pk):
    user = request.user
    room = Room.objects.get(id=pk)
    room_messages = room.message_set.all().order_by('created')
    participants = room.participants.all()
    room_messages_count = room_messages.count()
    test = room.message_set.filter(~Q(author = user)).count()
    context = {'room': room, 'room_messages': room_messages,
               'participants': participants,'count' : test}
    return render(request, 'base/room.html', context)


def userProfile(request, pk):
    user = User.objects.get(id=pk)
    friends = user.friends.all()
    room_messages = user.message_set.all()[:2]
    topics = Topic.objects.all()
    rooms = user.room_set.all()

    # pagination
    paginator = Paginator(rooms, 2)
    page_number = request.GET.get('page')
    test = paginator.get_page(page_number)

    context = {'user': user, 'rooms': rooms, 'room_messages': room_messages,
               'topics': topics, 'friends': friends, 'test': test}
    return render(request, 'base/profile.html', context)


@login_required(login_url='login')
def settings(request, pk):
    user = User.objects.get(id=pk)
    if request.method == "POST":
        myfile = request.FILES['avatar']
        fs = FileSystemStorage()
        name = fs.save(myfile.name, myfile)
        url = fs.url(name)
        user.avatar = name
        user.save()
        return redirect('user-profile', pk=user.id)
    else:
        context = {'user': user}
        return render(request, 'base/settings.html', context)


@login_required(login_url='login')
def createRoom(request):
    form = RoomForm()
    method = "Create"
    topics = Topic.objects.all()
    if request.method == 'POST':
        topic_name = request.POST.get('topic')
        if topic_name == "Other":
            topic = Topic.objects.create(name = request.POST.get("room_topic"))
        else:
            topic = Topic.objects.get(name = topic_name)
        room = Room.objects.create(
            host=request.user,
            topic=topic,
            name=request.POST.get('room_name'),
            description=request.POST.get('description'),
        )
        room.participants.add(request.user)
        room.save()
        return redirect('home')

    context = {'form': form, 'topics': topics, 'method': method}
    return render(request, 'base/room_form.html', context)


@login_required(login_url='login')
def updateRoom(request, pk):
    method = "Update"
    room = Room.objects.get(id=pk)
    form = RoomForm(instance=room)
    topics = Topic.objects.all()
    if request.user != room.host:
        return HttpResponse('You are not allowed here')
    if request.method == 'POST':
        topic_name = request.POST.get('topic')
        topic, created = Topic.objects.get_or_create(name=topic_name)
        room.name = request.POST.get('name')
        room.topic = topic
        room.description = request.POST.get('description')
        room.save()
        return redirect('home')
    context = {'form': form, 'topics': topics, 'method': method}
    return render(request, 'base/room_form.html', context)


@login_required(login_url='login')
def deleteRoom(request, pk):
    room = Room.objects.get(id=pk)
    if request.user != room.host:
        return HttpResponse('You are not allowed here')
    if request.method == "POST":
        room.delete()
        return redirect('home')
    return render(request, 'base/delete.html', {'obj': room})


@login_required(login_url='login')
def deleteMessage(request, pk):
    message = Message.objects.get(id=pk)
    if request.user != message.user:
        return HttpResponse('You are not allowed here')

    if request.method == "POST":
        message.delete()
        return redirect('home')
    return render(request, 'base/delete.html', {'obj': message})


@login_required(login_url='login')
def send_friend_request(request, pk):
    from_user = request.user
    to_user = User.objects.get(id=pk)
    friend_request, created = Friend_request.objects.get_or_create(
        from_user=from_user, to_user=to_user)
    to_user.requests.add(friend_request)
    from_user.requests.add(friend_request)
    if created:
        return redirect('home')
    else:
        return HttpResponse("friends request already send")


@login_required(login_url='login')
def accept_friend_request(request, pk):
    friend_request = Friend_request.objects.get(id=pk)
    if friend_request.to_user == request.user:
        friend_request.to_user.friends.add(friend_request.from_user)
        friend_request.from_user.friends.add(friend_request.to_user)
        friend_request.delete()
        return HttpResponse("accepted")
    else:
        return HttpResponse("not accepted")

@login_required(login_url='login')
def decline_friend_request(request, pk):
    friend_request = Friend_request.objects.get(id=pk)
    if friend_request.to_user == request.user:
        friend_request.delete()
        return HttpResponse("Declined")
    else:
        return HttpResponse("not declined")

@login_required(login_url='login')
def friends_view(request, pk):
    user = request.user
    friends = user.friends.all()
    context = {'user': user, 'friends': friends}
    return render(request, 'base/friends.html', context)

@login_required(login_url='login')
def unfriend(request, pk):
    user = request.user
    friend = User.objects.get(id=pk)
    user.friends.remove(friend)
    friend.friends.remove(user)
    return redirect('friends', pk=user.id)

def chat_view(request, pk):
    user = request.user
    to_user = User.objects.get(id=pk)
    friends = user.chat_with.all()
    user_messages = ChatMessage.objects.filter(author=user, reciever=to_user)
    to_user_messages = ChatMessage.objects.filter(
    author=to_user, reciever=user)
    to_user_messages.update(seen=True)
    message_count = to_user_messages.count()
    all_messages_count = (user_messages | to_user_messages).count()
    if(all_messages_count-50 > 0):
        chat_messages = (user_messages | to_user_messages).order_by('created')[all_messages_count-50:]
    else:
        chat_messages = (user_messages | to_user_messages).order_by('created')
    arr = []
    for friend in friends:
        temp = ChatMessage.objects.filter(
            seen=False, author=friend, reciever=user).count()
        arr.append(temp)
    foo = zip(friends, arr)
    context = {'user': user, 'to_user': to_user,'all_messages_count':all_messages_count,
               'chat_messages': chat_messages, 'foo': foo, 'message_count': message_count}
    return render(request, 'base/chat.html', context)

def createRoomMessage(request,pk):
    room = Room.objects.get(id=pk)
    user = request.user
    lastRoomMessage = room.message_set.all()
    if lastRoomMessage:
        lastMessageAuthor = lastRoomMessage[0].author.email
        lastMessageCreated = lastRoomMessage[0].created
    else:
        lastMessageAuthor = None
        lastMessageCreated = None
    response = {}
    if request.method == "POST":
        body = request.POST.get('body')
        message = Message(body=body, author=user, room = room)
        message.save()
        if (message.created-lastMessageCreated > datetime.timedelta(hours = 0, minutes = 1, seconds = 0)):
            timeDiff = True
        else:
            timeDiff = False
        created = message.created.strftime("%B %d %Y %I:%M p.m.")
        response = {"body":body,
                    "author":user.email,
                    "lastMessageAuthor":lastMessageAuthor,
                    "timeDiff":timeDiff,
                    "created":created
                    }
        if user not in room.participants.all():
            room.participants.add(user)
        return JsonResponse(response, safe=False)
    

def create(request, pk):
    user = request.user
    to_user = User.objects.get(id=pk)
    last_chat_message = ((ChatMessage.objects.filter(author=user, reciever=to_user)) | 
    (ChatMessage.objects.filter(author = to_user,reciever = user))).reverse()[0]
    lastMessageAuthor = last_chat_message.author.email
    lastMessageCreated = last_chat_message.created
    response = {}
    if request.method == "POST":
        body = request.POST.get('body')
        message = ChatMessage(body=body, author=user, reciever=to_user)
        message.save()
        messageTimeDiff = message.created-lastMessageCreated
        if(messageTimeDiff > datetime.timedelta(hours = 0, minutes = 1, seconds = 0)):
            timeDiff = True
        else:
            timeDiff = False
        created = message.created.strftime("%B %d %Y %I:%M p.m.")
        response = {"body":body,
                    "lastMessageAuthor":lastMessageAuthor,
                    "timeDiff":timeDiff,
                    "created":created
                    }
        if user not in to_user.chat_with.all():
            to_user.chat_with.add(user)
        if to_user not in user.chat_with.all():
            user.chat_with.add(to_user)
        return JsonResponse(response, safe=False)

def receive_chat_message(request,pk):
    user = request.user
    to_user = User.objects.get(id=pk)
    message = ChatMessage.objects.filter(author = to_user ,reciever = user)    
    if 'message' in request.GET:
        displayedMessageCount = int(request.GET['message'])
    allMessagesCount = len(message) 
    last_chat_message = ((ChatMessage.objects.filter(author=user, reciever=to_user)) | 
    (ChatMessage.objects.filter(author = to_user,reciever = user))).reverse()[allMessagesCount-displayedMessageCount]
    lastMessageAuthor = last_chat_message.author.email
    lastMessageCreated = last_chat_message.created    

    message_array = []
    timeDiff = False
    for index in range(displayedMessageCount,allMessagesCount):
        if (index == displayedMessageCount):
            messageTimeDiff = message[index].created - lastMessageCreated
        created = message[index].created.strftime("%B %d %Y %I:%M p.m.")
        message_array.append({"body": message[index].body,
                              "created" : created,
                              "author" : message[index].author.email,
                              "id" : message[index].author.id,
                              "username" : message[index].author.username,
                              "url": message[index].author.avatar.url})        
        if(messageTimeDiff > datetime.timedelta(hours = 0, minutes = 1, seconds = 0)):
            timeDiff = True
        else:
            timeDiff = False
    return JsonResponse({"message_array":message_array,"timeDiff" : timeDiff,
                         "lastMessageAuthor" : lastMessageAuthor},safe = False)

def receive_room_message(request,pk):
    user = request.user
    room = Room.objects.get(id = pk)
    room_messages = room.message_set.all().order_by('created')
    test = room.message_set.filter(~Q(author = user)).reverse()
    if 'message' in request.GET:
        displayedMessageCount = int(request.GET['message'])
    allMessagesCount = len(test) 
    last_chat_message = room_messages.reverse()[1]
    lastMessageAuthor = last_chat_message.author.email
    lastMessageCreated = last_chat_message.created    
    message_array = []
    timeDiff = False

    for index in range(displayedMessageCount,allMessagesCount):
        if (index == displayedMessageCount):
            messageTimeDiff = test[index].created - lastMessageCreated
        created = test[index].created.strftime("%B %d %Y %I:%M p.m.")
        message_array.append({"body": test[index].body,
                              "created" : created,
                              "author" : test[index].author.email,
                              "id" : test[index].author.id,
                              "username" : test[index].author.username,
                              "url": test[index].author.avatar.url})        
        if(messageTimeDiff > datetime.timedelta(hours = 0, minutes = 1, seconds = 0)):
            timeDiff = True
        else:
            timeDiff = False
    return JsonResponse({"message_array":message_array,"timeDiff" : timeDiff,
                         "lastMessageAuthor" : lastMessageAuthor},safe = False)

def load_more(request,pk,value):
    user = request.user
    to_user = User.objects.get(id=pk)
    print(value)
    message_array = []
    if value > 0 and (value-40) > 0:
        messages = (ChatMessage.objects.filter(author = to_user,reciever = user) 
        |ChatMessage.objects.filter(author = user,reciever = to_user))[value-40:value]
    elif value > 0 and (value-40) < 0:
        messages = (ChatMessage.objects.filter(author = to_user,reciever = user)|
        ChatMessage.objects.filter(author = user,reciever = to_user))[0:value]
    else:
        messages = []

    for message in messages:
        tmp = { "author": message.author.username,
                "body" : message.body,
                "created" : message.created,
                "seen" : message.seen       
        }
        message_array.append(tmp)
    print(messages)
    return JsonResponse(message_array,safe = False)

def delete_from_chat(request, pk):
    user = request.user
    to_user = User.objects.get(id=pk)
    user.chat_with.remove(to_user)
    next = user.chat_with.all().first()
    return redirect('chat', pk=next.id)