from django.contrib import admin
from django.urls import path, include 
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls), 
    path('', include('base.urls'))
]
handler404 = 'base.views.error_404_view'
urlpatterns+= static(settings.MEDIA_URL,document_root = settings.MEDIA_ROOT)