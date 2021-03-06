from django.urls import path, re_path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('book/search', views.search, name='search'),
    re_path('book/(?P<isbn>[0-9]{13})/details', views.details, name='book details'),
    path('host/login', views.host_login, name='host login'),
    path('host/homepage', views.host_homepage, name='host homepage'),
    path('host_admin/manage', views.host_manage, name='host manage'),
    path('host_admin/order/finish', views.finish, name='finish'),
    path('host_admin/order/repeal', views.repeal, name='repeal'),
    path('user/register', views.register, name='register'),
    path('user/login', views.login, name='login'),
    path('user/passResetTokenGen', views.pass_reset_token_gen, name='reset password'),
    path('user/setNewPass', views.get_new_pass, name='reset password'),
    path('user/passReset', views.pass_reset, name='reset password'),
    path('user/<username>/homepage', views.homepage, name='homepage'),
    path('user/<username>/updatePass', views.update_pass, name='update user pass'),
    path('user/<username>/updateName', views.update_name, name='update user pass'),
    path('user/<username>/chart/removeItem', views.delete_item, name='remove item'),
    path('user/<username>/listGenerate', views.list_generate, name='order generate'),
    path('user/<username>/chart/addItem', views.add_item, name='add item to chart'),
    path('user/<username>/order/delete', views.order_delete, name='user order delete'),
    path('user/<username>/order/repay', views.order_repay, name='repay'),
    path('user/<username>/signout', views.signout, name='sign out'),
    path('bank_receipt/pi', views.bank_receipt, name='bank receipt'),
    path('ca/double_receive', views.double_receive, name='receive double sign from ca'),
    path('api/get', views.api_verification_code, name='get verification code'),
    path('api/verify', views.api_verification_verify, name='verify user inputted code')
]
