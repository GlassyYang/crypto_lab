from django.urls import path, re_path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('search', views.search, name='search'),
    path('result', views.result, name="search result"),
    path('host_admin/manage', views.host_manage, name='host manage'),
    path('host_admin/order/finish', views.finish, name='finish'),
    path('host_admin/order/repeal', views.repeal, name='repeal'),
    path('user/register', views.register, name='register'),
    path('user/login', views.login, name='login'),
    path('user/<username>/homepage', views.homepage, name='homepage'),
    path('user/<username>/chart/removeItem', views.delete_item, name='remove item'),
    path('user/<username>/listGenerate', views.list_generate, name='order generate'),
    path('user/<username>/chart/addItem', views.add_item, name='add item to chart'),
    re_path('book/(?P<isbn>[0-9]{13})/details', views.details, name='book details'),
    path('user/<username>/signout', views.signout, name='sign out'),
    path('host/login', views.host_login, name='host login'),
    path('host/homepage', views.host_homepage, name='host homepage'),
    path('bank_receipt/pi', views.bank_receipt, name='bank receipt')
]
