from django.urls import path

from . import views

urlpatterns = [
    path('', views.upload, name='upload'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('library/', views.library, name='library'),
    path('library/<int:document_id>/share/', views.library_share, name='library_share'),
    path('library/<int:document_id>/delete/', views.library_delete, name='library_delete'),
    path(
        'library/<int:document_id>/ciphertext/',
        views.library_ciphertext,
        name='library_ciphertext',
    ),
    path('created/<str:token>/', views.created, name='created'),
    path('f/<str:token>/', views.download, name='download'),
    path('delete/<str:token>/', views.delete_now, name='delete_now'),
    path('api/library/init/', views.library_upload_init, name='library_upload_init'),
    path('api/library/upload/<int:document_id>/', views.library_upload_bytes, name='library_upload_bytes'),
    path('api/library/finalize/', views.library_upload_finalize, name='library_upload_finalize'),
    path(
        'api/library/<int:document_id>/share/init/',
        views.library_share_init,
        name='library_share_init',
    ),
    path('api/library/share/<str:token>/upload/', views.share_upload_bytes, name='share_upload_bytes'),
    path('api/uploads/init/', views.upload_init, name='upload_init'),
    path('api/uploads/finalize/', views.upload_finalize, name='upload_finalize'),
    path('api/shares/<str:token>/access/', views.object_access, name='object_access'),
]
