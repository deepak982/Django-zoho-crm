from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login, name='login'),
    path('callback/', views.callback, name='callback'),
    path('create-lead/', views.create_lead, name='create_lead'),
    path('delete-lead/<str:lead_id>/', views.delete_lead, name='delete_lead'),
    path('leads/', views.leads, name='leads'),
    path('', views.index, name='index'),
]
