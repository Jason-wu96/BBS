from django.conf.urls import url
from app01 import views
urlpatterns =[
    url(r'up_down/',views.up_down),
    url(r'comment/',views.comment),

    url(r'(\w+)/article/(\d+)/$', views.article_detail),

    url(r'(\w+)/category/(\w+)/$', views.article_category),

    url(r'(\w+)/tag/(\w+)/$', views.article_tags),

    url(r'(\w+)/archive/(.+)/$', views.article_archive),



    url(r'(\w+)/$', views.home)

]