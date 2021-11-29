from django import urls
from django.contrib import admin
from django.urls import path
from django.urls.conf import include

urlpatterns = [
    path('',include('detector_site.urls')),
    path('processing',include('detector_site.urls')),
    path('results',include('detector_site.urls')),
    path('admin/', admin.site.urls),
]
