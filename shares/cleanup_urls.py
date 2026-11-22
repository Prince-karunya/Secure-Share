from django.urls import path

from .views import vercel_cleanup

urlpatterns = [
    path('', vercel_cleanup, name='vercel_cleanup'),
]
