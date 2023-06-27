from django.urls import path
from . import views

urlpatterns = [

    path('login/',views.loginPage, name = 'login'),
    path('logout/',views.logoutUser, name = 'logout'),
    path('register/',views.registerPage, name = 'register'),
    path('',views.home, name = 'home'),
    path('room/<str:pk>',views.room, name = 'room'),  
    path('create-room/',views.createRoom, name = 'create-room'),
    path('profile/<str:pk>',views.userProfile, name = 'user-profile'),
    path('update-room/<str:pk>',views.updateRoom, name = 'update-room'),
    path('delete-room/<str:pk>',views.deleteRoom, name = 'delete-room'),
    path('delete-message/<str:pk>',views.deleteMessage, name = 'delete-message'),
    path('settings/<str:pk>',views.settings, name = 'settings'),
    path('settings/<str:pk>/password-change',views.passwordChange, name = 'password-change'),
    path('topics/',views.topics, name = 'topics'),
    path('login/forget-password',views.forget_passwordPage, name = 'forget_password'),
    path('activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/',  
    views.activate, name='activate'),  
    path('login/forget-password/sent',views.passwordEmailView, name = 'password_email'),
    #Friend requests paths
    path('send_friend_request/<str:pk>/',views.send_friend_request, name = 'send-friend-request'),
    path('accept_friend_request/<str:pk>/',views.accept_friend_request, name = 'accept-friend-request'),
    
    path('profile/<str:pk>/friends',views.friends_view,name = 'friends'),
    path('unfriend/<str:pk>',views.unfriend,name = 'unfriend'),



    #Room
    path('room/<str:pk>/create',views.createRoomMessage,name = "createRoomMessage"),
    path('room/<str:pk>/receive_message',views.receive_room_message,name = "receive_room_message"),


    #Chat
    path('create/<str:pk>',views.create,name = "create"),
    path('receive_message/<str:pk>',views.receive_chat_message,name = "receive_message"),
    path('chat/<str:pk>',views.chat_view,name = 'chat'),
    path('delete_from_chat/<str:pk>/',views.delete_from_chat,name = 'delete-from-chat'),
    ]

