"""osiete_osint URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include

from rest_framework import routers

from osiete_osint.apps.service import views

router = routers.DefaultRouter()
router.register(r'services', views.api_service_page)
router.register(r'data', views.api_datalist_page)
router.register(r'vt_osint', views.api_vt_osint)
router.register(r'dangerous_osint', views.api_dangerous_data_list)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.top_page),
    path('api/', include(router.urls)),
    path('api-auth/', include('rest_framework.urls')),
    path('osints/api', views.osint_list),
]
