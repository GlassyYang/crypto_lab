from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse, HttpResponseRedirect
from django.core.validators import validate_email
from django.core.exceptions import ValidationError

import urllib3
import certifi
import json
import random
from urllib3 import PoolManager
import bcrypt
import re
from base64 import b64encode, b64decode
from os.path import exists

# 加密库
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from bookstore import models
# 证书注册链接
certificate_sign = 'http://192.168.43.59:8000/ca/trader_register'

# 根据机构名称获取证书的链接
sertificate_query = '/ca/require'

# 自己的证书和秘钥，和网站名
certificate_self = ''
key = ''
web_name = "SunShine Bookstore"

# CA根证书
cert_root = ''
cert_root_file = 'certificate_root.cert'
# 自己的卡号
card = "2163 7862 8138 7868"

# 使用的豆瓣API
isbn_api = 'https://api.douban.com/v2/book/isbn/'
search_api = 'https://api.douban.com/v2/book/search'

# 使用的代理连接
https: PoolManager = urllib3.PoolManager(cert_reqs="CERT_REQUIRED", ca_certs=certifi.where())
http = urllib3.PoolManager()

# 用户名格式：
format_user = re.compile('[a-zA-Z0-9_]{8,20}')
format_pass = re.compile('[a-zA-Z0-9_!@#%]')

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
            book = models.Books.objects.create(isbn=data['isbn13'], title=data['title'], author=json.dumps({'author': data['author']}),
                                subtitle=data['subtitle'], summary=data['summary'], author_intro=data['author_intro'],
                                rating=data['rating']['average'], pubdate=data['pubdate'], publisher=data['publisher'],
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
            book = models.Books.objects.create(isbn=data['isbn13'], title=data['title'], author=json.dumps({'author': data['author']}),
                                subtitle=data['subtitle'], summary=data['summary'], author_intro=data['author_intro'],
                                rating=data['rating']['average'], pubdate=data['pubdate'], publisher=data['publisher'],
                                price=price, tags=json.dumps({'tags': tags}), pages=data['pages'],
                                binding=data['binding'], image_s=data['images']['small'],
                                image_m=data['images']['medium'])
            book.save()
        recommend.append(book.serialize())
    tags = json.loads(setting.category)
    books_list = {}
    for key, tag in tags.items():
        r = https.request('GET', search_api, fields={'tag': tag, 'count': 6, 'offset': random.randint(0, 100)})
        if r.status != 200:
            raise RuntimeError(r.data)
        books = json.loads(r.data)['books']
        books_list[key] = books
    items_list = []
    for i in range(4):
        r = https.request('GET', search_api, fields={'tag': '推荐', 'count': 10, 'offset':  i * 10})
        if r.status != 200:
            raise RuntimeError(r.data)
        books = json.loads(r.data)['books']
        items_list.append(books)
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


def register(request):
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
            return HttpResponse('succeed')
        else:
            return HttpResponse('parameters error!')
    return HttpResponse("same email has exist!")


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
        return HttpResponse('GET method rejected.')
    order_id = request.POST.get('id', '')
    if order_id == '':
        return HttpResponse('no reasonable parameters!')
    print("data received is: " + str(len(order_id)) + order_id)
    return HttpResponse("data received is: " + order_id)


@csrf_exempt
def finish(request):
    if request.method != 'POST':
        return HttpResponse('GET method rejected.')
    order_id = request.POST.get('id', '')
    if order_id == '':
        return HttpResponse('no reasonable parameters!')
    print('data received is:' + str(len(order_id)) + order_id)
    return HttpResponse("data received is: " + order_id)


def host_manage(request):
    return render(request, 'homepage_host.html', {'user': 'ZhangYang'})


def homepage(request, username):
    user = request.session.get('username', '')
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
    fields = {
        'username': username,
        'chart': chart,
        'orders': orders,
    }
    return render(request, 'homepage.html', fields)


def add_item(request, username):
    user = request.session.get('username', '')
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
    print('data received is:' + item_isbn)
    return HttpResponse('data received is:' + item_isbn)


@csrf_exempt
def list_generate(request, username):
    user = request.session.get('username', '')
    if user == '' or user != username:
        return HttpResponse("Page Not Found1", status=404)
    if request.method != 'POST':
        return HttpResponse("Page Not Found2", status=404)
    item_list = json.loads(request.body).get('list', '')
    if item_list == '':
        return HttpResponse("Page Not Found4", status=404)
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
        print(cur_user.chart.all().filter(isbn=isbn))
        if len(cur_user.chart.all().filter(isbn=isbn)) == 0:
            return HttpResponse("isbn error!2")
        cur_user.chart.remove(book)
        books.append(book)
        total += float(book.price)
    order = models.Order(username=user, user_id=user_id, total=total, status='W')
    order.save()
    for book in books:
        order.contain.add(book)
    order.save()
    global certificate_self
    global key
    global cert_root_file
    global cert_root
    global key_file
    if cert_root == '':
        if not exists(cert_root_file):      # 说明还没有在CA处进行注册
            if exists(key_file):
                f = open(key_file, "rb")
                data = f.read()
                key = RSA.import_key(data, passphrase="ZhAm@wd%3&28")
                f.close()
            else:       # 进行注册
                key = RSA.generate(1024)
                f = open(key_file, 'wb')
                data = key.exportKey(passphrase="ZhAm@wd%3&28", pkcs=8, protection="scryptAndAES128-CBC")
                f.write(data)
                f.close()
            fields = {
                'DN': web_name,
                "publickey": key.publickey().exportKey('PEM')
            }
            r = http.request("GET", certificate_sign, fields=fields)
            if r.status != 200:
                return HttpResponse("CA certificate Error!", status=500)
            with open(cert_root_file, 'wb') as f:
                f.write(data)
            cert_root = json.loads(r.data)
        else:
            with open(cert_root_file, 'rb') as f:
                data = f.read()
                cert_root = json.loads(data)
    if certificate_self == '':
        pass
    aes_key = get_random_bytes(16)
    enc = AES.new(aes_key, AES.MODE_CBC, aes_key)
    global card     # 卡号
    sha = SHA256.new()
    total = str(total)
    sha.update(b64encode(total.encode('utf-8')))   # 对卡号进行sha256散列
    sha.update(b64encode(card.encode('utf-8')))     # 对卡号进行sha256散列
    total = b64encode(enc.encrypt(pad(total.encode('utf-8'), AES.block_size))).decode('utf-8')
    enc = AES.new(aes_key, AES.MODE_CBC, aes_key)
    card = b64encode(enc.encrypt(pad(card.encode('utf-8'), AES.block_size))).decode('utf-8')
    rsaenc = PKCS1_v1_5.new(key)
    fields = {
        'amount': total,
        'card': card,
        'signature': sha.hexdigest(),
        'certificate': certificate_self,          # 我的证书
        'aes_key': b64encode(rsaenc.encrypt(aes_key)).decode('utf-8'),     # 加密的AES秘钥，用你的公钥加密
    }
    print(fields)
    return HttpResponse(json.dumps(fields))


def result(request):
    return render(request, "result.html", {'user': "ZhangYang"})


def details(request, isbn):
    try:
        book = models.Books.objects.get(isbn=isbn)
    except models.Books.DoesNotExist:
        r = https.request("GET", isbn_api + isbn)
        if r.status != 200:
            return HttpResponse("cannot find the book", status=404)
        data = json.loads(r.data)
        price = data['price'][:(len(data['price']) - 1)]
        tags = []
        for i in range(min(len(data['tags']), 4)):
            tags.append(data['tags'][i]['name'])
        book = models.Books.objects.create(isbn=data['isbn13'], title=data['title'], author=json.dumps({'author': data['author']}),
                            subtitle=data['subtitle'], summary=data['summary'], author_intro=data['author_intro'],
                            rating=data['rating']['average'], pubdate=data['pubdate'], publisher=data['publisher'],
                            price=price, tags=json.dumps({'tags': tags}), pages=data['pages'],
                            binding=data['binding'], image_s=data['images']['small'], image_m=data['images']['medium'])
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


def login(request):
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
    except models.Users.objects.DoesNotExist:
        return HttpResponse("email or password not correct!")
    if bcrypt.hashpw(passwd.encode('utf-8'), user.password.encode('utf-8')).decode('utf-8') != user.password:
        return HttpResponse("email or password not correct!")
    request.session['user_id'] = user.id
    request.session['username'] = user.username
    return HttpResponse("succeed")


def signout(request, username):
    user = request.session.get('username', '')
    if user == '' or username != user:
        return HttpResponse("Not Found", status=404)
    del request.session['username']
    del request.session['user_id']
    referrer = request.META.get("HTTP_REFERER", '')
    if referrer == '':
        return HttpResponseRedirect('/')
    return HttpResponseRedirect(referrer)
