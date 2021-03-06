from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
import certifi
import json
import random
from urllib3 import PoolManager
import bcrypt
import re
import datetime
from os.path import exists

# 加密库
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from bookstore import models
from bookstore.lib import crypto
from bookstore.lib import verify_api

# 证书注册链接
certificate_sign = 'http://192.168.43.59:8000/ca/trader_register'

# 根据机构名称获取证书的链接
sertificate_query = 'http://192.168.43.59:8000/ca/require'

# 请求CA对指定的消息进行签名的链接
ca_sign_link = 'http://192.168.43.59:8000/ca/return_url/'

# 自己的证书和秘钥，和网站名
certificate_self = None
self_key = None
web_name = "SunShine Bookstore"
bank_web_name = 'Virtual Bank'
# CA根证书
cert_root = None
cert_root_file = 'certificate_root.pem'
# 自己的卡号
card = "2163 7862 8138 7868"

# bank的根证书
bank_key = None

# bank的支付页面:
bank_charge = "http://192.168.43.96:8000/authen/deal/"
# bank的确认页面：
bank_verify = "http://192.168.43.96:8000/authen/pay_transfer/"
# 使用的豆瓣API
isbn_api = 'https://api.douban.com/v2/book/isbn/'
search_api = 'https://api.douban.com/v2/book/search'

# 使用的代理连接
https: PoolManager = PoolManager(cert_reqs="CERT_REQUIRED", ca_certs=certifi.where())
http = PoolManager()

aes_key = ''

# 用户名格式：
format_user = re.compile('[a-zA-Z0-9_]{8,20}')
format_pass = re.compile('[a-zA-Z0-9_!@#%]{8, 20}')

# RSA秘钥文件
key_file = 'key.pem'


def index(request):
    try:
        setting = models.IndexSetting.objects.get(id=1)
    except models.IndexSetting.DoesNotExist:
        return HttpResponse("Server Inner Error!", status=500)
    isbn_list = setting.carousel.split(',')
    carousel = []
    for i in range(len(isbn_list)):
        try:
            book = models.Books.objects.get(isbn=isbn_list[i])
        except models.Books.DoesNotExist:
            r = https.request("GET", isbn_api + isbn_list[i])
            if r.status != 200:
                raise RuntimeError('request error!')
            data = json.loads(r.data)
            price = data['price']
            price = price[:(len(price) - 1)]
            tags = []
            for j in range(min(len(data['tags']), 4)):
                tags.append(data['tags'][j]['name'])
            book = models.Books.objects.create(isbn=data['isbn13'], title=data['title'],
                                               author=json.dumps({'author': data['author']}),
                                               subtitle=data['subtitle'], summary=data['summary'],
                                               author_intro=data['author_intro'],
                                               rating=data['rating']['average'], pubdate=data['pubdate'],
                                               publisher=data['publisher'],
                                               price=price, tags=json.dumps({'tags': tags}), pages=data['pages'],
                                               binding=data['binding'], image_s=data['images']['small'],
                                               image_m=data['images']['medium'])
            book.save()
        carousel.append(book.serialize())
    recommend_list = []
    recommend_list.extend(setting.big_image.split(','))
    recommend_list.extend(setting.small_image.split(','))
    recommend = []
    for i in range(len(recommend_list)):
        try:
            book = models.Books.objects.get(isbn=recommend_list[i])
        except models.Books.DoesNotExist:
            r = https.request("GET", isbn_api + recommend_list[i])
            if r.status != 200:
                raise RuntimeError('request error!')
            data = json.loads(r.data)
            price = data['price']
            price = price[:(len(price) - 1)]
            tags = []
            for j in range(min(len(data['tags']), 4)):
                tags.append(data['tags'][j]['name'])
            book = models.Books.objects.create(isbn=data['isbn13'], title=data['title'],
                                               author=json.dumps({'author': data['author']}),
                                               subtitle=data['subtitle'], summary=data['summary'],
                                               author_intro=data['author_intro'],
                                               rating=data['rating']['average'], pubdate=data['pubdate'],
                                               publisher=data['publisher'],
                                               price=price, tags=json.dumps({'tags': tags}), pages=data['pages'],
                                               binding=data['binding'], image_s=data['images']['small'],
                                               image_m=data['images']['medium'])
            book.save()
        recommend.append(book.serialize())
    tags = json.loads(setting.category)
    books_list = {}
    for key, tag in tags.items():
        r = https.request('GET', search_api, fields={'tag': tag, 'count': 6, 'start': random.randint(0, 100)})
        if r.status != 200:
            raise RuntimeError(r.data)
        books = json.loads(r.data)['books']
        books_list[key] = books
    items_list = []
    for i in range(4):
        r = https.request('GET', search_api, fields={'tag': '推荐', 'count': 10, 'start': i * 10})
        if r.status != 200:
            raise RuntimeError(r.data)
        books = json.loads(r.data)['books']
        items_list.append(books)
    # with open('test.json', 'wb') as f:
    #     f.write(str(items_list).encode())
    user = request.session.get('username', '')
    if user == '':
        res = {
            'carousel_list': carousel,
            'recommend_list': recommend,
            'tags': tags,
            'books_list': books_list,
            'items_list': items_list
        }
    else:
        res = {
            'username': user,
            'carousel_list': carousel,
            'recommend_list': recommend,
            'tags': tags,
            'books_list': books_list,
            'items_list': items_list
        }
    return render(request, "index.html", res)


@csrf_exempt
def register(request):
    print(request.body)
    if len(request.GET) == 0 and len(request.POST) == 0:
        return render(request, "register.html", {})
    if request.method == 'GET':
        user = request.GET.get('username', '')
        email = request.GET.get('email', '')
        passwd = request.GET.get('password', '')
    else:
        user = request.POST.get('username', '')
        email = request.POST.get('email', '')
        passwd = request.POST.get('password', '')
    if email == '' or passwd == '' or user == '':
        return HttpResponse("Not Found", status=404)
    try:
        validate_email(email)
    except ValidationError:
        return HttpResponse("parameters error!")
    try:
        user = models.Users.objects.get(email=email)
    except models.Users.DoesNotExist:
        if format_user.match(user) and format_pass.match(passwd):
            passwd = bcrypt.hashpw(passwd.encode('utf-8'), bcrypt.gensalt(rounds=14))
            user = models.Users(username=user, password=passwd.decode('utf-8'), email=email)
            user.save()
            request.session['user_id'] = user.id
            request.session['username'] = user.username
            return HttpResponse('注册成功！')
        else:
            return HttpResponse('parameters error!', status=400)
    return HttpResponse("已经存在相同的邮箱，请直接登录或选择新的邮箱注册！", status=400)


# 定义搜索页面
def search(request):
    if len(request.GET) == 0 and len(request.POST) == 0:
        return render(request, "search.html", {'logged_in': False})
    elif len(request.GET) != 0:
        question = request.GET.get('q', '')
        if question == '':
            return HttpResponse("No reasonable parameters transformed.")
    elif len(request.POST) != 0:
        question = request.POST.get('q', '')
        if question == '':
            return HttpResponse("No reasonable parameters transformed.")
    try:
        setting = models.IndexSetting.objects.get(id=1)
    except models.IndexSetting.DoesNotExist:
        return HttpResponse("Service Internal Error", status=500)
    fields = {
        'q': question,
        'count': setting.search_pages * setting.search_pages_items
    }
    r = https.request("GET", search_api, fields=fields)
    if r.status != 200:
        return HttpResponse("cannot execute query because of api restriction", status=500)
    data = json.loads(r.data)
    pages = []
    count = data['count']
    books = data['books']
    for i in range(min(setting.search_pages, count // setting.search_pages_items)):
        ind = i * setting.search_pages_items
        temp = []
        for j in range(min(setting.search_pages_items, count - ind)):
            temp.append(books[ind + j])
        pages.append(temp)
    user = request.session.get('username', '')
    if user == '':
        fields = {
            'q': question,
            'pages': pages
        }
    else:
        fields = {
            'username': 'ZhangYang',
            'pages': pages
        }
    return render(request, 'result.html', fields)


@csrf_exempt
def repeal(request):
    if request.method != 'POST':
        return HttpResponse('GET method rejected.', status=400)
    order_id = request.POST.get('id', '')
    reason = request.POST.get("reason", '')
    if order_id == '' or reason == '':
        return HttpResponse('no reasonable parameters!', status=400)
    try:
        order = models.Order.objects.get(id=order_id)
    except models.Order.DoesNotExist:
        return HttpResponse('order id error!', status=400)
    order.status = 'R'
    order.repeal_reason = reason
    order.save()
    return HttpResponse("data received is: " + order_id)


@csrf_exempt
def finish(request):
    if request.method != 'POST':
        return HttpResponse('GET method rejected.')
    order_id = request.POST.get('id', '')
    if order_id == '':
        return HttpResponse('no reasonable parameters!')
    try:
        order = models.Order.objects.get(id=order_id)
    except models.Order.DoesNotExist:
        return HttpResponse("订单还未生成，或网站内部错误！", status=400)
    order.status = 'F'
    order.save()
    return HttpResponse("订单已经完成！")


def host_manage(request):
    return render(request, 'homepage_host.html', {'user': 'ZhangYang'})


def homepage(request, username):
    redirected = False
    user = request.session.get('username', '')
    ident = request.GET.get('deal_identify', '')
    if ident != '':
        order_id = crypto.ident_get(self_key, ident)
        if order_id == -1:
            return HttpResponse("deal_identify error!", status=400)
        try:
            order = models.Order.objects.get(id=order_id)
        except models.Order.DoesNotExist:
            return HttpResponse("deal_identify error!", status=400)
        order.status = "W"
        order.save()
        redirected = True
    if user == '' or user != username:
        return HttpResponse("Page Not Found")
    user_id = request.session.get('user_id', '')
    if user_id == '':
        return HttpResponse("server error!", status=404)
    try:
        user = models.Users.objects.get(id=user_id)
    except models.Users.DoesNotExist:
        return HttpResponse("server error!", status=404)
    chart = user.chart.all()
    orders = models.Order.objects.filter(user_id=user_id)
    orders_deal = []
    cur_time = datetime.datetime.now()
    for order in orders:
        timelocal = order.time.replace(tzinfo=None)
        temp = {
            'order': order,
            'time_deal': timedeal(timelocal, cur_time)
        }
        orders_deal.append(temp)
    fields = {
        'redirected': redirected,
        'username': username,
        'chart': chart,
        'orders_deal': orders_deal,
    }
    return render(request, 'homepage.html', fields)


def add_item(request, username):
    user = request.session.get('username', '')
    # 安全措施
    if user == '' or user != username:
        return HttpResponse("Page Not Found", status=404)
    if len(request.GET) == 0 and len(request.POST) == 0:
        return HttpResponse("parameters error!", status=400)
    if request.method == 'GET':
        isbn = request.GET.get('isbn', '')
    else:
        isbn = request.POST.get('isbn', '')
    if isbn == '':
        return HttpResponse("parameters error!", status=400)
    user_id = request.session['user_id']
    try:
        user = models.Users.objects.get(id=user_id)
    except models.Users.DoesNotExist:
        return HttpResponse("server inner error", status=500)
    if len(user.chart.all().filter(isbn=isbn)) > 0:
        return HttpResponse("该书已经在你的购物车中！")
    try:
        book = models.Books.objects.get(isbn=isbn)
    except models.Books.DoesNotExist:
        return HttpResponse("server inner error", status=500)
    user.save()
    user.chart.add(book)
    user.save()
    return HttpResponse("succeed")


@csrf_exempt
def delete_item(request, username):
    user = request.session.get('username' '')
    if user == '' or username != user:
        return HttpResponse("Page Not Found", status=404)
    if request.method != "POST":
        return HttpResponse('GET method rejected.')
    item_isbn = request.POST.get('isbn', '')
    if item_isbn == '':
        HttpResponse("no reasonable parameters!")
    try:
        book = models.Books.objects.get(isbn=item_isbn)
    except models.Books.DoesNotExist:
        return HttpResponse("book identified ob isbn isn't exist!", status=500)
    user_id = request.session.get('user_id', '')
    if user_id == '':
        return HttpResponse("Server Inner Error!", status=500)
    try:
        user = models.Users.objects.get(id=user_id)
    except models.Users.objects.DoesNotExist:
        return HttpResponse("Server Inner Error!", status=500)
    user.chart.remove(book)
    return HttpResponse('succeed')


@csrf_exempt
def list_generate(request, username):
    user = request.session.get('username', '')
    # 安全措施，当访问该页面的用户不是页面指定的用户的时候，阻止其访问
    if user == '' or user != username:
        return HttpResponse("Page Not Found", status=404)
    if request.method != 'POST':
        return HttpResponse("Page Not Found", status=404)
    item_list = json.loads(request.body).get('list', '')
    if item_list == '':
        return HttpResponse("Page Not Found", status=404)
    books = []
    total = 0
    user_id = request.session.get('user_id', '')
    if user_id == '':
        return HttpResponse("Server Error!", status=500)
    try:
        cur_user = models.Users.objects.get(id=user_id)
    except models.Users.DoesNotExist:
        return HttpResponse("Server Error!", status=500)
    for isbn in item_list:
        try:
            book = models.Books.objects.get(isbn=isbn)
        except models.Books.DoesNotExist:
            return HttpResponse("isbn error!1")
        if len(cur_user.chart.all().filter(isbn=isbn)) == 0:
            return HttpResponse("isbn error!2")
        cur_user.chart.remove(book)
        books.append(book)
        total += float(book.price)
    order = models.Order(username=user, user_id=user_id, total=total, status='P')
    order.save()
    order.order_oi = crypto.oi_generate(order)
    for book in books:
        order.contain.add(book)
    order.save()
    response = certificate_gen()
    if response is not True:
        return HttpResponse(response, status=500)
    global card  # 卡号
    total = str(total)
    global aes_key
    aes_key = get_random_bytes(16)
    print(aes_key)
    total_c = crypto.enc_msg(aes_key, total)
    card_c = crypto.enc_msg(aes_key, card)
    fields = {
        'amount': total_c,
        'card': card_c,
        'signature': crypto.sign(self_key, [total_c, card_c]),
        'certificate': json.dumps(certificate_self),  # 我的证书
        'aes_key': crypto.pub_enc_msg(bank_key, aes_key),  # 加密的AES秘钥，用你的公钥加密
        'deal_identify': crypto.ident_gen(self_key, str(order.id))
    }
    req = http.request("POST", bank_charge, fields=fields)
    if req.status != 200:
        return HttpResponse("pay link redirect error!", status=500)
    pay_id = json.loads(req.data)['pay_id']
    order.pay_id = pay_id
    order.save()
    return HttpResponse(pay_id)


def details(request, isbn):
    try:
        book = models.Books.objects.get(isbn=isbn)
    except models.Books.DoesNotExist:
        r = https.request("GET", isbn_api + isbn)
        if r.status != 200:
            return HttpResponse("cannot find the book", status=404)
        data = json.loads(r.data)
        price = data['price']
        while not price[-1].isdigit():
            price = price[:-1]
        while not price[0].isdigit():
            price = price[1:]
        tags = []
        for i in range(min(len(data['tags']), 4)):
            tags.append(data['tags'][i]['name'])
        book = models.Books.objects.create(isbn=data['isbn13'], title=data['title'],
                                           author=json.dumps({'author': data['author']}),
                                           subtitle=data['subtitle'], summary=data['summary'],
                                           author_intro=data['author_intro'],
                                           rating=data['rating']['average'], pubdate=data['pubdate'],
                                           publisher=data['publisher'],
                                           price=price, tags=json.dumps({'tags': tags}), pages=data['pages'],
                                           binding=data['binding'], image_s=data['images']['small'],
                                           image_m=data['images']['medium'])
        book.save()
    book = book.serialize()
    book['tags'] = json.loads(book['tags'])['tags']
    book['author'] = json.loads(book['author'])['author']
    rand = random.randint(0, len(book['tags']) - 1)
    r = https.request("GET", search_api, fields={'tag': book['tags'][rand], 'count': 3})
    if r.status != 200:
        raise RuntimeError('times limited!')
    data = json.loads(r.data)
    user = request.session.get('username', '')
    if user == '':
        fields = {
            'book': book,
            'recommend': data['books']
        }
    else:
        fields = {
            'username': user,
            'book': book,
            'recommend': data['books']
        }
    return render(request, 'details.html', fields)


@csrf_exempt
def login(request):
    print(request.body)
    if len(request.GET) == 0 and len(request.POST) == 0:
        return HttpResponse("Not Found", status=404)
    if request.method == 'GET':
        email = request.GET.get('email', '')
        passwd = request.GET.get('password', '')
    else:
        email = request.POST.get('email', '')
        passwd = request.POST.get('password', '')
    if email == '' or passwd == '':
        return HttpResponse("Not Found", status=404)
    try:
        user = models.Users.objects.get(email=email)
    except models.Users.DoesNotExist:
        return HttpResponse("email or password not correct!", status=400)
    if bcrypt.hashpw(passwd.encode('utf-8'), user.password.encode('utf-8')).decode('utf-8') != user.password:
        return HttpResponse("email or password not correct!", status=400)
    request.session['user_id'] = user.id
    request.session['username'] = user.username
    return HttpResponse("succeed")


def signout(request, username):
    user = request.session.get('username', '')
    if user == '' or username != user:
        return HttpResponse("Not Found", status=404)
    del request.session['username']
    del request.session['user_id']
    return redirect('/')


def host_login(request):
    return render(request, 'login_host.html', {})


def host_homepage(request):
    if request.method == 'GET':
        return HttpResponse("Page Not Found", status=404)
    if len(request.POST) == 0:
        return HttpResponse("Page Not Found", status=404)
    user = request.POST.get('username', '')
    passwd = request.POST.get('password', '')
    if user == '' or passwd == '':
        return HttpResponse("parameter not reasonable!")
    try:
        user_in = models.Host.objects.get(id=1)
    except models.Host.DoesNotExist:
        return HttpResponse("Server Inner Error!", status=500)
    if user != user_in.username:
        return HttpResponse("username or password incorrect!1")
    passwd_in = user_in.password.encode('utf-8')
    if bcrypt.hashpw(passwd.encode('utf-8'), passwd_in) != passwd_in:
        return HttpResponse("username or password incorrect!2")
    orders = models.Order.objects.all().exclude(status='P')
    num_fin = 0
    num_wait = 0
    total = 0
    for order in orders:
        total += float(order.total)
        if order.status == 'F':
            num_fin += 1
        else:
            num_wait += 1
    orders = orders.filter(status='W')
    orders_deal = []
    now = datetime.datetime.now()
    for order in orders:
        timelocal = order.time.replace(tzinfo=None)
        temp = {
            'order': order,
            'day_time': timedeal(timelocal, now),
        }
        orders_deal.append(temp)

    fields = {
        'username': 'bookstore administrator',
        'orders': orders_deal,
        'total': total,
        'num_wait': num_wait,
        'num_fin': num_fin
    }
    return render(request, 'homepage_host.html', fields)


@csrf_exempt
def update_pass(request, username):
    user_in = request.session.get('username', '')
    user_id = request.session.get('user_id', '')
    if user_in == '' or user_id == '':
        return HttpResponse("Page Not Found", status=404)
    if user_in != username:
        return HttpResponse("Page Not Found", status=404)
    try:
        user = models.Users.objects.get(id=user_id)
    except models.Users.DoesNotFound:
        return HttpResponse("Server Inner Error!", status=500)
    if request.method != 'POST':
        return HttpResponse("Parameter Error!", status=500)
    old_pass = request.POST.get('old_pass', '')
    new_pass = request.POST.get('new_pass', '')
    if old_pass == '' or new_pass == '':
        return HttpResponse("Parameter Error!", status=500)
    if bcrypt.hashpw(old_pass.encode(), user.password.encode()) != user.password.encode():
        return HttpResponse("输入的原密码错误！", status=400)
    user.password = bcrypt.hashpw(new_pass.encode(), bcrypt.gensalt(rounds=14)).decode()
    user.save()
    return HttpResponse("success")


def update_name(request, username):
    if request.method != 'GET':
        return HttpResponse("Bad Request", status=400)
    user = request.session.get('username', '')
    user_id = request.session.get('user_id', '')
    if user == '' or user_id == '' or username != user:
        return HttpResponse("Page Not Found", status=404)
    try:
        user_in = models.Users.objects.get(id=user_id)
    except models.Users.DoesNotExist:
        return HttpResponse("Server Inner Error", status=500)
    new_username = request.GET.get('new_name', '')
    if new_username == '':
        return HttpResponse("Bad Request", status=400)
    if not format_user.match(new_username):
        return HttpResponse("Bad Username Format", status=400)
    user_in.username = new_username
    user_in.save()
    request.session['username'] = new_username
    return HttpResponse("success")


def pass_reset_token_gen(request):
    global self_key
    if request.method == 'POST':
        return HttpResponse("Page Not Found", status=400)
    email = request.GET.get('email', '')
    if email == '':
        return HttpResponse("Page Not Found", status=400)
    try:
        user = models.Users.objects.get(email=email)
    except models.Users.DoesNotExist:
        return HttpResponse("当前邮箱没有在本站注册用户！", status=400)
    if self_key is None:
        if exists(key_file):
            f = open(key_file, "rb")
            data = f.read()
            self_key = RSA.import_key(data, passphrase="ZhAm@wd%3&28")
            f.close()
        else:
            return HttpResponse("Current Server haven't get a key!")
    token = crypto.email_token_gen(self_key, user)
    url = request.get_host() + '/user/setNewPass?token=' + token
    print(url)
    if verify_api.send_email(http, email, url):
        return HttpResponse("邮件发送成功！")
    return HttpResponse("邮件发送失败！", status=500)


@csrf_exempt
def pass_reset(request):
    global self_key
    if request.method == 'GET':
        return HttpResponse("Page Not Found1", status=404)
    token = request.POST.get('token', '')
    email = crypto.get_email(self_key, token)
    if token == '':
        return HttpResponse("Page Not Found2", status=404)
    if email is None:
        return HttpResponse("密码重置连接已经过期，请重新进行密码重置操作！", status=400)
    new_pass = request.POST.get('new_pass', '')
    if new_pass == '':
        return HttpResponse("Parameters Error!", status=400)
    try:
        user = models.Users.objects.get(email=email)
    except models.Users.DoesNotExist:
        return HttpResponse("Server Inner Error!", status=500)
    user.password = bcrypt.hashpw(new_pass.encode(), bcrypt.gensalt(rounds=14))
    return HttpResponse("设置密码成功！")


def get_new_pass(request):
    if request.method != 'GET':
        return HttpResponse("Page Not Found1", status=404)
    token = request.GET.get('token', '')
    if token == '':
        return HttpResponse("Page Not Found2", status=404)
    return render(request, 'reset_password.html', {'token': token})


@csrf_exempt
def bank_receipt(request):
    if request.method != "POST":
        return HttpResponse("transform data error", status=400)
    pi = request.POST.get('hashPI', '')
    ident = request.POST.get('deal_identify', '')
    if pi == '' or ident == '':
        return HttpResponse('transform parameters isn\'t correct!', status=400)
    global aes_key
    pi = crypto.dec_msg(aes_key, pi)
    ident = crypto.dec_msg(aes_key, ident)
    order_id = crypto.ident_get(self_key, ident)
    if order_id == -1:
        return HttpResponse("id verify has lost efficacy", status=400)
    try:
        order = models.Order.objects.get(id=order_id)
    except models.Order.DoesNotExist:
        return HttpResponse("Inner error!", status=500)
    oi = order.order_oi
    pi = pi
    order.order_pi = pi
    order.save()
    unsign = pi + oi
    fields = {
        'url': "http://192.168.43.160:8000/user/" + order.username + '/homepage',
        'message': unsign,
        "DN": ident
    }
    req = http.request("POST", ca_sign_link, fields=fields)
    if req.status != 200:
        return HttpResponse("double sign request error!", status=500)
    return HttpResponse(req.data)


@csrf_exempt
def double_receive(request):
    if request.method != 'POST':
        return HttpResponse("Page Not Found", status=404)
    ident = request.POST.get('deal_identify', '')
    cert = request.POST.get('cert', '')
    signed = request.POST.get('sign', '')
    if ident == '' or signed == '' or cert == '':
        return HttpResponse('transform parameters isn\'t correct!', status=400)
    order_id = crypto.ident_get(self_key, ident)
    print('order id is:')
    print(order_id)
    if order_id == -1:
        return HttpResponse('ident has been destroyed', status=400)
    try:
        order = models.Order.objects.get(id=order_id)
    except models.Order.DoesNotExist:
        return HttpResponse('ident has been destroyed', status=400)
    cert = json.loads(cert)
    if not crypto.cert_verify(cert, cert_root):
        return HttpResponse("verify certificate failed", status=400)
    if not crypto.verify_double_sign(cert['publickey'], order, signed):
        return HttpResponse("verify double signature failed", status=400)
    if order_id == -1:
        return HttpResponse("The order identify has been destroyed", status=400)
    try:
        order = models.Order.objects.get(id=order_id)
    except models.Order.DoesNotExist:
        return HttpResponse("The order identify has been destroyed", status=400)
    pay_id = order.pay_id
    if not pay_id:
        return HttpResponse("Server Inner Error!", status=500)
    global aes_key
    order_oi = crypto.enc_msg(aes_key, order.order_oi)
    signed = crypto.enc_msg(aes_key, signed)
    fields = {
        'hashOI': order_oi,
        'sign': signed,
        'cert': json.dumps(cert)
    }
    req = http.request("POST", bank_verify + pay_id + '/', fields=fields)
    if req.status != 200:
        return HttpResponse("bank verify sign failed!", status=400)
    if req.data == b'success':
        return HttpResponse("success")
    else:
        return HttpResponse("bank verify sign failed!", status=400)


def api_verification_code(request):
    data = verify_api.get_verify_code(http)
    if data is None:
        return HttpResponse("get verification code failed!", status=500)
    return HttpResponse(data)


def api_verification_verify(request):
    if request.method == "POST":
        return HttpResponse("Page Not Found", status=404)
    c_id = request.GET.get('captcha_id', '')
    c_code = request.GET.get('captcha_code', '')
    if c_id == '' or c_code == '':
        return HttpResponse("Not reasonable ")
    data = verify_api.verify_code(http, c_id, c_code)
    if data is None:
        return HttpResponse("verify inputted code Error!", status=500)
    return HttpResponse(data)


def order_delete(request, username):
    user_in = request.session.get('username', '')
    if user_in != username:
        return HttpResponse("Page Not Found", status=404)
    if request.method != 'GET':
        return HttpResponse("Page Not Found!", status=404)
    order_id = request.GET.get('id', '')
    if order_id == '':
        return HttpResponse("parameters isn't reasonable!", status=404)
    try:
        order = models.Order.objects.get(id=order_id)
    except models.Order.DoesNotExist:
        return HttpResponse("parameters isn't reasonable!", status=404)
    if order.username != username:
        return HttpResponse('Page Not Found', status=404)
    order.delete()
    return HttpResponse("succeed")


def order_repay(request, username):
    order_id = request.GET.get("id", '')
    if order_id == '':
        return HttpResponse('Not Found', status=404)
    user_in = request.session.get('username', '')
    if user_in == '' or username != user_in:
        return HttpResponse("Not Found", status=404)
    user_id = request.session.get('user_id', '')
    response = certificate_gen()
    if response is not True:
        return HttpResponse(response)
    try:
        order = models.Order.objects.get(id=order_id)
    except models.Order.DoesNotExist:
        return HttpResponse("Wrong ideal identify!", status=400)
    # 进行检查，如果订单所属用户不是当前的用户，不允许其修改
    if order.user_id != user_id:
        return HttpResponse("You Have No right to repay this order!", status=400)
    global card  # 卡号
    total = str(order.total)
    global aes_key
    aes_key = get_random_bytes(16)
    print(aes_key)
    total_c = crypto.enc_msg(aes_key, total)
    card_c = crypto.enc_msg(aes_key, card)
    fields = {
        'amount': total_c,
        'card': card_c,
        'signature': crypto.sign(self_key, [total_c, card_c]),
        'certificate': json.dumps(certificate_self),  # 我的证书
        'aes_key': crypto.pub_enc_msg(bank_key, aes_key),  # 加密的AES秘钥，用你的公钥加密
        'deal_identify': crypto.ident_gen(self_key, str(order.id))
    }
    req = http.request("POST", bank_charge, fields=fields)
    if req.status != 200:
        return HttpResponse("pay link redirect error!", status=500)
    pay_id = json.loads(req.data)['pay_id']
    order.pay_id = pay_id
    order.save()
    return HttpResponse(pay_id)


def timedeal(begin_time, end_time):
    temp = end_time - begin_time
    days = temp.days
    hours = temp.seconds // 3600
    return str(days) + "天" + str(hours) + "小时"


def certificate_gen():
    global certificate_self
    global self_key
    global cert_root_file
    global cert_root
    global key_file
    global bank_key
    if cert_root is None:
        print('into this')
        if not exists(cert_root_file):      # 说明还没有在CA处进行注册
            if exists(key_file):
                f = open(key_file, "rb")
                data = f.read()
                self_key = RSA.import_key(data, passphrase="ZhAm@wd%3&28")
                f.close()
            else:
                self_key = RSA.generate(1024)
                with open(key_file, 'wb') as f:
                    data = self_key.exportKey(passphrase="ZhAm@wd%3&28", pkcs=8, protection="scryptAndAES128-CBC")
                    f.write(data)
            fields = {
                'DN': web_name,
                "publickey": self_key.publickey().exportKey('PEM')
            }
            r = http.request("POST", certificate_sign, fields=fields)
            if r.status != 200:
                return "CA certificate Error!"
            with open(cert_root_file, 'wb') as f:
                data = json.loads(r.data)
                print(r.data)
                f.write(json.dumps(data['certInfo']).encode())
            cert_root = data['certInfo']
        else:
            with open(cert_root_file, 'rb') as f:
                data = f.read()
                cert_root = json.loads(data)
            with open(key_file, 'rb') as f:
                data = f.read()
                self_key = RSA.import_key(data, passphrase="ZhAm@wd%3&28")
    if certificate_self is None:
        req = http.request("POST", sertificate_query, fields={'DN': web_name})
        if req.status != 200:
            return "CA certificate query error!"
        certificate_self = json.loads(req.data.decode('utf-8'))['certInfo']
    print("bank key is:")
    print(bank_key)
    if bank_key is None:
        print("into this")
        req = http.request("POST", sertificate_query, fields={'DN': bank_web_name})
        if req.status != 200:
            return "CA certificate query error!"
        cert = json.loads(req.data.decode('utf-8'))['certInfo']
        if crypto.cert_verify(cert, cert_root):
            bank_key = RSA.import_key(cert['publickey'])
        else:
            return "Banks certificate verify error!"
    return True
