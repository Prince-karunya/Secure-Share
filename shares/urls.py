from django.urls import path

from . import views

urlpatterns = [
    path('', views.upload, name='upload'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('created/<str:token>/', views.created, name='created'),
    path('f/<str:token>/', views.download, name='download'),
    path('delete/<str:token>/', views.delete_now, name='delete_now'),
    path('api/uploads/init/', views.upload_init, name='upload_init'),
    path('api/uploads/finalize/', views.upload_finalize, name='upload_finalize'),
    path('api/shares/<str:token>/access/', views.object_access, name='object_access'),
]
