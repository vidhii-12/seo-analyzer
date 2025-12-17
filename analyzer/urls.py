from django.urls import path
from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("keyword-check/", views.keyword_check, name="keyword_check"),
    path("download-csv/", views.download_csv, name="download_csv"),
]
