from django.db import models

# Create your models here.


# 用于存储用户信息的表，包括购物车
class Users(models.Model):
    id = models.AutoField(primary_key=True)
    username = models.CharField(max_length=50)
    password = models.CharField(max_length=50)
    email = models.EmailField()
    chart = models.ManyToManyField("Books")


# 用作豆瓣图书的缓存，以突破豆瓣API的限制
class Books(models.Model):
    isbn = models.CharField(max_length=15, unique=True)
    title = models.CharField(max_length=50)
    author = models.CharField(max_length=50)
    subtitle = models.CharField(max_length=50)
    summary = models.TextField()
    author_intro = models.TextField()
    rating = models.CharField(max_length=5)
    publisher = models.CharField(max_length=100)
    pubdate = models.CharField(max_length=10)
    price = models.CharField(max_length=10)
    tags = models.CharField(max_length=500)
    pages = models.CharField(max_length=10)
    binding = models.CharField(max_length=50)
    image_s = models.CharField(max_length=100)
    image_m = models.CharField(max_length=100)

    def serialize(self):
        return dict([(attr, getattr(self, attr)) for attr in [f.name for f in self._meta.fields]])


# 生成的订单
class Order(models.Model):
    ORDER_STATUS = (
        ("P", "等待客户支付"),
        ("W", "支付完成，等待店主发货"),
        ("F", "已发货，请注意接收")
    )
    user_id = models.IntegerField()
    username = models.CharField(max_length=50)
    total = models.DecimalField(max_digits=10, decimal_places=2)
    time = models.DateTimeField(auto_now=True)
    status = models.CharField(max_length=1, choices=ORDER_STATUS)
    order_oi = models.CharField(max_length=100, null=True)
    order_pi = models.CharField(max_length=100, null=True)
    pay_id = models.CharField(max_length=50, null=True)
    contain = models.ManyToManyField("Books")


# 用于存储网站管理员用户名和密码的表
class Host(models.Model):
    username = models.CharField(max_length=50)
    password = models.CharField(max_length=50)


# 定义的用于保存主页设置的表
class IndexSetting(models.Model):
    carousel = models.CharField(max_length=50)
    big_image = models.CharField(max_length=50)
    small_image = models.CharField(max_length=50)
    category = models.CharField(max_length=100)
    search_pages = models.IntegerField()
    search_pages_items = models.IntegerField()
