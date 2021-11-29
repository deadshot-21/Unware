from os import name
from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
     path('',views.home,name='home'),
     path('processing',views.upload,name='upload'),
     path('result',views.result,name='result'),
    #  path('printPDF',views.printPDF,name='printPDF')
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)